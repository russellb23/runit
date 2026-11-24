use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use lettre::{
    message::{header::ContentType, Mailbox},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use std::{env, net::{IpAddr, SocketAddr}, time::Duration};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(sqlx::FromRow)]
struct DueRun {
    id: Uuid,
    tenant_id: Uuid,
    incident_id: Uuid,
    policy_id: Uuid,
    step_index: i32,
    cycle: i32,
}

#[derive(sqlx::FromRow)]
struct Policy {
    id: Uuid,
    name: String,
    steps: Value,
    repeat_count: i32,
    repeat_every_minutes: i32,
}

#[derive(Deserialize)]
struct Step {
    delay_minutes: i32,
    target_type: String,
    target: String,
}

#[derive(sqlx::FromRow)]
struct Recipient {
    id: Uuid,
    handle: String,
    channel: String,
    destination: String,
}

#[derive(sqlx::FromRow)]
struct Job {
    id: Uuid,
    tenant_id: Uuid,
    incident_id: Uuid,
    channel: String,
    destination: String,
    payload: Value,
    attempts: i32,
    max_attempts: i32,
}

pub async fn run_worker(db: PgPool) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "notification HTTP client could not start");
            return;
        }
    };
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        if let Err(error) = process_due_escalations(&db).await {
            tracing::error!(%error, "escalation scheduler iteration failed");
        }
        if let Err(error) = deliver_pending(&db, &client).await {
            tracing::error!(%error, "notification delivery iteration failed");
        }
    }
}

async fn process_due_escalations(db: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    let due = sqlx::query_as::<_, DueRun>(r#"
        SELECT id,tenant_id,incident_id,policy_id,step_index,cycle FROM incident_escalations
        WHERE status='active' AND next_run_at <= now()
        ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT 25
    "#).fetch_all(&mut *tx).await?;

    for run in due {
        let incident = sqlx::query_as::<_, (String, i64, String, String, String, String, String)>(
            "SELECT status,incident_number,title,description,severity,source,service FROM incidents WHERE id=$1 AND tenant_id=$2")
            .bind(run.incident_id).bind(run.tenant_id).fetch_optional(&mut *tx).await?;
        let Some((status,incident_number,title,description,severity,source,service)) = incident else {
            sqlx::query("UPDATE incident_escalations SET status='cancelled',updated_at=now() WHERE id=$1")
                .bind(run.id).execute(&mut *tx).await?;
            continue;
        };
        if status != "triggered" {
            sqlx::query("UPDATE incident_escalations SET status='cancelled',updated_at=now() WHERE id=$1")
                .bind(run.id).execute(&mut *tx).await?;
            continue;
        }
        let policy = sqlx::query_as::<_, Policy>("SELECT id,name,steps,repeat_count,repeat_every_minutes FROM escalation_policies WHERE id=$1 AND tenant_id=$2")
            .bind(run.policy_id).bind(run.tenant_id).fetch_optional(&mut *tx).await?;
        let Some(policy) = policy else {
            sqlx::query("UPDATE incident_escalations SET status='cancelled',last_error='policy deleted',updated_at=now() WHERE id=$1")
                .bind(run.id).execute(&mut *tx).await?;
            continue;
        };
        let parsed: Vec<Step> = match serde_json::from_value::<Vec<Step>>(policy.steps.clone()) {
            Ok(steps) if !steps.is_empty() => steps,
            _ => {
                sqlx::query("UPDATE incident_escalations SET status='cancelled',last_error='invalid policy steps',updated_at=now() WHERE id=$1")
                    .bind(run.id).execute(&mut *tx).await?;
                continue;
            }
        };
        let index = run.step_index.max(0) as usize;
        let Some(step) = parsed.get(index) else {
            sqlx::query("UPDATE incident_escalations SET status='completed',updated_at=now() WHERE id=$1")
                .bind(run.id).execute(&mut *tx).await?;
            continue;
        };
        let recipients = match step.target_type.as_str() {
            "team" => sqlx::query_as::<_, Recipient>("SELECT id,handle,channel,destination FROM notification_recipients WHERE tenant_id=$1 AND active AND (team=$2 OR $2=ANY(groups)) ORDER BY handle,channel")
                .bind(run.tenant_id).bind(&step.target).fetch_all(&mut *tx).await?,
            "schedule" => {
                let schedule=sqlx::query_as::<_,(Uuid,DateTime<Utc>,i32)>("SELECT id,rotation_starts_at,rotation_interval_minutes FROM on_call_schedules WHERE tenant_id=$1 AND (id::text=$2 OR name=$2) LIMIT 1")
                    .bind(run.tenant_id).bind(&step.target).fetch_optional(&mut *tx).await?;
                if let Some((schedule_id,starts_at,rotation_minutes))=schedule {
                    let members=sqlx::query_scalar::<_,String>("SELECT handle FROM on_call_schedule_members WHERE schedule_id=$1 ORDER BY position")
                        .bind(schedule_id).fetch_all(&mut *tx).await?;
                    let elapsed=(Utc::now()-starts_at).num_seconds();
                    if !members.is_empty()&&elapsed>=0 {
                        let slot=(elapsed/(i64::from(rotation_minutes)*60)) as usize % members.len();
                        sqlx::query_as::<_,Recipient>("SELECT id,handle,channel,destination FROM notification_recipients WHERE tenant_id=$1 AND active AND handle=$2 ORDER BY channel")
                            .bind(run.tenant_id).bind(&members[slot]).fetch_all(&mut *tx).await?
                    } else { Vec::new() }
                } else { Vec::new() }
            }
            _ => sqlx::query_as::<_, Recipient>("SELECT id,handle,channel,destination FROM notification_recipients WHERE tenant_id=$1 AND active AND (handle=$2 OR destination=$2) ORDER BY handle,channel")
                .bind(run.tenant_id).bind(&step.target).fetch_all(&mut *tx).await?,
        };
        if recipients.is_empty() {
            sqlx::query("UPDATE incident_escalations SET next_run_at=now()+interval '1 minute',last_error=$2,updated_at=now() WHERE id=$1")
                .bind(run.id).bind(format!("no active notification targets for {}", step.target)).execute(&mut *tx).await?;
            tracing::warn!(incident_id=%run.incident_id, target=%step.target, "escalation has no active recipients; retrying target lookup in one minute");
            continue;
        }
        let payload = json!({
            "event":"incident.escalation",
            "text":format!("RLY-{:08} [{}] {} — {}",incident_number,severity,title,service),
            "incident":{"id":run.incident_id,"incident_number":format!("RLY-{:08}",incident_number),"title":title,"description":description,"severity":severity,"source":source,"service":service,"status":status},
            "policy":{"id":policy.id,"name":policy.name},
            "step":{"index":index+1,"target_type":step.target_type,"target":step.target,"cycle":run.cycle+1}
        });
        for recipient in &recipients {
            sqlx::query(r#"INSERT INTO notification_outbox
                (escalation_run_id,tenant_id,incident_id,cycle,step_index,recipient_id,channel,destination,payload)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (escalation_run_id,cycle,step_index,recipient_id)
                DO UPDATE SET channel=EXCLUDED.channel,destination=EXCLUDED.destination,payload=EXCLUDED.payload,
                  status='pending',attempts=0,next_attempt_at=now(),locked_at=NULL,delivered_at=NULL,last_error=''"#)
                .bind(run.id).bind(run.tenant_id).bind(run.incident_id).bind(run.cycle).bind(run.step_index).bind(recipient.id)
                .bind(&recipient.channel).bind(&recipient.destination).bind(payload.clone()).execute(&mut *tx).await?;
        }
        let recipients_text = recipients.iter().map(|r| r.handle.as_str()).collect::<Vec<_>>().join(", ");
        sqlx::query("INSERT INTO incident_events (incident_id,kind,actor,note) VALUES ($1,'escalation_queued','relayops', $2)")
            .bind(run.incident_id).bind(format!("Step {} queued to {} recipient(s): {}", index+1, recipients.len(), recipients_text)).execute(&mut *tx).await?;

        if index + 1 < parsed.len() {
            let next = &parsed[index+1];
            sqlx::query("UPDATE incident_escalations SET step_index=$2,next_run_at=now()+make_interval(mins=>$3),last_error='',updated_at=now() WHERE id=$1")
                .bind(run.id).bind((index+1) as i32).bind(next.delay_minutes).execute(&mut *tx).await?;
        } else if run.cycle < policy.repeat_count {
            sqlx::query("UPDATE incident_escalations SET step_index=0,cycle=cycle+1,next_run_at=now()+make_interval(mins=>$2),last_error='',updated_at=now() WHERE id=$1")
                .bind(run.id).bind(policy.repeat_every_minutes).execute(&mut *tx).await?;
        } else {
            sqlx::query("UPDATE incident_escalations SET status='completed',last_error='',updated_at=now() WHERE id=$1")
                .bind(run.id).execute(&mut *tx).await?;
        }
    }
    tx.commit().await
}

async fn deliver_pending(db: &PgPool, client: &reqwest::Client) -> Result<(), sqlx::Error> {
    // Recover jobs whose worker disappeared while holding a lease.
    sqlx::query("UPDATE notification_outbox SET status='pending',locked_at=NULL WHERE status='sending' AND locked_at < now()-interval '10 minutes'")
        .execute(db).await?;
    let jobs = sqlx::query_as::<_, Job>(r#"
        WITH selected AS (
          SELECT id FROM notification_outbox WHERE status='pending' AND next_attempt_at<=now()
          ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 5
        )
        UPDATE notification_outbox o SET status='sending',locked_at=now(),attempts=o.attempts+1
        FROM selected s WHERE o.id=s.id
        RETURNING o.id,o.tenant_id,o.incident_id,o.channel,o.destination,o.payload,o.attempts,o.max_attempts
    "#).fetch_all(db).await?;
    for job in jobs {
        let incident_status: Option<String> = sqlx::query_scalar("SELECT status FROM incidents WHERE id=$1 AND tenant_id=$2")
            .bind(job.incident_id).bind(job.tenant_id).fetch_optional(db).await?;
        if incident_status.as_deref() != Some("triggered") {
            sqlx::query("UPDATE notification_outbox SET status='cancelled',locked_at=NULL,last_error='incident acknowledged or resolved' WHERE id=$1")
                .bind(job.id).execute(db).await?;
            continue;
        }
        match deliver_one(client, &job).await {
            Ok(()) => {
                sqlx::query("UPDATE notification_outbox SET status='delivered',delivered_at=now(),locked_at=NULL,last_error='' WHERE id=$1")
                    .bind(job.id).execute(db).await?;
                sqlx::query("INSERT INTO incident_events (incident_id,kind,actor,note) VALUES ($1,'notification_delivered','relayops',$2)")
                    .bind(job.incident_id).bind(format!("{} delivered to {}", job.channel, job.destination)).execute(db).await?;
            }
            Err(error) => {
                let dead = job.attempts >= job.max_attempts;
                let delay = (30_i32.saturating_mul(1_i32.checked_shl((job.attempts-1).clamp(0,10) as u32).unwrap_or(1024))).min(3600);
                sqlx::query("UPDATE notification_outbox SET status=$2,next_attempt_at=now()+make_interval(secs=>$3),locked_at=NULL,last_error=$4 WHERE id=$1")
                    .bind(job.id).bind(if dead {"dead"} else {"pending"}).bind(delay).bind(error.chars().take(1000).collect::<String>()).execute(db).await?;
                sqlx::query("INSERT INTO incident_events (incident_id,kind,actor,note) VALUES ($1,'notification_delivery_failed','relayops',$2)")
                    .bind(job.incident_id).bind(format!("{} attempt {}{}: {}", job.channel, job.attempts, if dead {" (dead letter)"} else {"; retry scheduled"}, error.chars().take(500).collect::<String>())).execute(db).await?;
                tracing::warn!(job_id=%job.id,attempt=job.attempts,dead,error=%error,"notification delivery failed");
            }
        }
    }
    Ok(())
}

async fn deliver_one(client: &reqwest::Client, job: &Job) -> Result<(), String> {
    match job.channel.as_str() {
        "email" => send_email(job).await,
        "webhook" => send_webhook(client, job).await,
        other => Err(format!("unsupported notification channel: {other}")),
    }
}

async fn send_email(job: &Job) -> Result<(), String> {
    let smtp_url = env::var("SMTP_URL").map_err(|_| "SMTP_URL is not configured".to_string())?;
    let from = env::var("SMTP_FROM").map_err(|_| "SMTP_FROM is not configured".to_string())?;
    let from: Mailbox = from.parse().map_err(|e| format!("invalid SMTP_FROM: {e}"))?;
    let to: Mailbox = job.destination.parse().map_err(|e| format!("invalid email destination: {e}"))?;
    let title = job.payload.pointer("/incident/title").and_then(Value::as_str).unwrap_or("Incident notification");
    let incident_id = job.payload.pointer("/incident/id").and_then(Value::as_str).unwrap_or_default();
    let incident_number = job.payload.pointer("/incident/incident_number").and_then(Value::as_str).unwrap_or(incident_id);
    let body = serde_json::to_string_pretty(&job.payload).map_err(|e| e.to_string())?;
    let message = Message::builder().from(from).to(to).subject(format!("[RelayOps {incident_number}] {title}"))
        .header(ContentType::TEXT_PLAIN).body(format!("Escalation notification for incident {incident_number} (internal ID {incident_id}).\n\n{body}"))
        .map_err(|e| format!("could not build email: {e}"))?;
    let sender = AsyncSmtpTransport::<Tokio1Executor>::from_url(&smtp_url)
        .map_err(|e| format!("invalid SMTP_URL: {e}"))?.build();
    sender.send(message).await.map(|_|()).map_err(|e|format!("SMTP delivery failed: {e}"))
}

async fn send_webhook(client: &reqwest::Client, job: &Job) -> Result<(), String> {
    let secret=env::var("WEBHOOK_SIGNING_SECRET").map_err(|_| "WEBHOOK_SIGNING_SECRET is not configured".to_string())?;
    if secret.len()<32 { return Err("WEBHOOK_SIGNING_SECRET must be at least 32 characters".into()); }
    let url=reqwest::Url::parse(&job.destination).map_err(|e|format!("invalid webhook URL: {e}"))?;
    if url.scheme()!="https" { return Err("webhook URL must use HTTPS".into()); }
    let Some(host)=url.host_str() else { return Err("webhook URL has no host".into()) };
    {
        if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") || host.ends_with(".local") {
            return Err("local webhook destinations are blocked".into());
        }
    }
    let port=url.port_or_known_default().unwrap_or(443);
    let resolved:Vec<SocketAddr>=tokio::net::lookup_host((host,port)).await
        .map_err(|e|format!("webhook host lookup failed: {e}"))?.collect();
    if resolved.is_empty() || resolved.iter().any(|addr|!is_public_address(addr.ip())) {
        return Err("webhook host must resolve only to public IP addresses".into());
    }
    // Pin this request to the validated address to prevent a second DNS lookup from
    // resolving the configured host to a private address.
    let pinned=resolved[0];
    let client=if host.parse::<IpAddr>().is_err() {
        reqwest::Client::builder().timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none()).resolve(host,pinned).build()
            .map_err(|e|format!("could not create webhook client: {e}"))?
    } else { client.clone() };
    let body=serde_json::to_vec(&job.payload).map_err(|e|e.to_string())?;
    let timestamp=Utc::now().timestamp().to_string();
    let mut mac=HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e|e.to_string())?;
    mac.update(timestamp.as_bytes());mac.update(b".");mac.update(&body);
    let signature=hex::encode(mac.finalize().into_bytes());
    let response=client.post(url).header("content-type","application/json")
        .header("x-relayops-timestamp",timestamp)
        .header("x-relayops-signature",format!("sha256={signature}"))
        .body(body).send().await.map_err(|e|format!("webhook request failed: {e}"))?;
    if !response.status().is_success(){return Err(format!("webhook returned HTTP {}",response.status()))}
    Ok(())
}

fn is_public_address(ip:IpAddr)->bool {
    match ip {
        IpAddr::V4(v)=>{
            let o=v.octets();
            !(v.is_private()||v.is_loopback()||v.is_link_local()||v.is_unspecified()||v.is_broadcast()||v.is_multicast()
                ||o[0]==0||(o[0]==100&&o[1]>=64&&o[1]<=127)||(o[0]==198&&(o[1]==18||o[1]==19))
                ||(o[0]==192&&o[1]==0&&o[2]==0)||(o[0]==192&&o[1]==0&&o[2]==2)
                ||(o[0]==198&&o[1]==51&&o[2]==100)||(o[0]==203&&o[1]==0&&o[2]==113)||o[0]>=224)
        }
        IpAddr::V6(v)=>!(v.is_loopback()||v.is_unique_local()||v.is_unicast_link_local()||v.is_unspecified()||v.is_multicast()),
    }
}


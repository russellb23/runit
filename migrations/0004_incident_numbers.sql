CREATE SEQUENCE incident_number_seq START WITH 1;
ALTER TABLE incidents ADD COLUMN incident_number bigint;
UPDATE incidents SET incident_number=nextval('incident_number_seq');
ALTER TABLE incidents ALTER COLUMN incident_number SET DEFAULT nextval('incident_number_seq');
ALTER TABLE incidents ALTER COLUMN incident_number SET NOT NULL;
ALTER SEQUENCE incident_number_seq OWNED BY incidents.incident_number;
CREATE UNIQUE INDEX incidents_incident_number_idx ON incidents(incident_number);

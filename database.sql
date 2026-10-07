CREATE DATABASE accessguard;

USE accessguard;

-- USERS
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    department VARCHAR(100),
    role_id INT,
    status VARCHAR(20) DEFAULT 'Active'
);

-- ROLES
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL
);

-- PERMISSIONS
CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL
);

-- ROLE PERMISSIONS
CREATE TABLE role_permissions (
    role_id INT,
    permission_id INT,
    PRIMARY KEY (role_id, permission_id)
);

-- ACCESS REQUESTS
CREATE TABLE access_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    resource VARCHAR(100),
    reason TEXT,
    status VARCHAR(20) DEFAULT 'Pending',
    expiry_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AUDIT LOGS
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100),
    resource VARCHAR(100),
    result VARCHAR(30),
    description TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- SECURITY ALERTS
CREATE TABLE security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    alert_type VARCHAR(100),
    description TEXT,
    severity VARCHAR(30),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DEFAULT ROLES
INSERT INTO roles (role_name) VALUES
('Admin'),
('Manager'),
('Employee'),
('Intern'),
('Guest');

-- DEFAULT PERMISSIONS
INSERT INTO permissions (resource, action) VALUES
('Payroll', 'READ'),
('Payroll', 'WRITE'),
('Employee Records', 'READ'),
('Employee Records', 'WRITE'),
('Project Files', 'READ'),
('Project Files', 'WRITE'),
('HR Documents', 'READ'),
('System Settings', 'READ'),
('System Settings', 'WRITE'),
('Company News', 'READ');

-- ADMIN PERMISSIONS
INSERT INTO role_permissions
SELECT 1, id FROM permissions;

-- MANAGER
INSERT INTO role_permissions
SELECT 2, id
FROM permissions
WHERE resource IN ('Payroll', 'Employee Records', 'Project Files', 'HR Documents')
AND action = 'READ';

-- EMPLOYEE
INSERT INTO role_permissions
SELECT 3, id
FROM permissions
WHERE resource IN ('Project Files', 'Company News');

-- INTERN
INSERT INTO role_permissions
SELECT 4, id
FROM permissions
WHERE resource IN ('Project Files', 'Company News')
AND action = 'READ';

-- GUEST
INSERT INTO role_permissions
SELECT 5, id
FROM permissions
WHERE resource = 'Company News';

SELECT * FROM roles;
SELECT * FROM permissions;
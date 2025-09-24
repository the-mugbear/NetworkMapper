# NetworkMapper API Documentation

This document provides a detailed overview of the NetworkMapper API. The API is designed to be RESTful and uses JSON for all requests and responses.

**Base URL:** `/api/v1`

## Authentication

The NetworkMapper API uses JSON Web Tokens (JWT) for authentication. To access protected endpoints, you must include an `Authorization` header with a Bearer token in your request.

**Example:** `Authorization: Bearer <your_access_token>`

## Endpoints

### Authentication (`/auth`)

Endpoints for user authentication, session management, and user administration.

---

#### **Login**

-   **Endpoint:** `POST /auth/login`
-   **Description:** Authenticates a user and returns a JWT access token.
-   **Authentication:** None
-   **Request Body:**
    ```json
    {
      "username": "string",
      "password": "string"
    }
    ```
-   **Responses:**
    -   `200 OK`: Successful authentication.
        ```json
        {
          "access_token": "string",
          "token_type": "bearer",
          "expires_in": 28800,
          "user": {
            "id": "integer",
            "username": "string",
            "email": "string",
            "full_name": "string",
            "role": "string"
          }
        }
        ```
    -   `401 Unauthorized`: Invalid credentials.

---

#### **Logout**

-   **Endpoint:** `POST /auth/logout`
-   **Description:** Logs out the current user by revoking their session.
-   **Authentication:** Required (any role)
-   **Responses:**
    -   `200 OK`:
        ```json
        {
          "message": "Successfully logged out"
        }
        ```

---

#### **Register New User**

-   **Endpoint:** `POST /auth/register`
-   **Description:** Registers a new user. This action is restricted to administrators.
-   **Authentication:** Required (Admin role)
-   **Request Body:**
    ```json
    {
      "username": "string",
      "email": "user@example.com",
      "password": "string",
      "full_name": "string"
    }
    ```
-   **Responses:**
    -   `200 OK`: User successfully registered. Returns the new user's profile.
    -   `400 Bad Request`: Username or email already exists, or the password does not meet strength requirements.

---

#### **Get User Profile**

-   **Endpoint:** `GET /auth/profile`
-   **Description:** Retrieves the profile of the currently authenticated user.
-   **Authentication:** Required (any role)
-   **Responses:**
    -   `200 OK`: Returns the user's profile information.

---

#### **Change Password**

-   **Endpoint:** `POST /auth/change-password`
-   **Description:** Allows a user to change their own password.
-   **Authentication:** Required (any role)
-   **Request Body:**
    ```json
    {
      "current_password": "string",
      "new_password": "string"
    }
    ```
-   **Responses:**
    -   `200 OK`:
        ```json
        {
          "message": "Password successfully changed"
        }
        ```
    -   `400 Bad Request`: The current password is incorrect or the new password is not strong enough.

---

### Audit Logs (`/audit`)

Endpoints for viewing audit logs and statistics.

---

#### **Get Audit Logs**

-   **Endpoint:** `GET /audit/logs`
-   **Description:** Retrieves a paginated list of audit logs. Restricted to administrators.
-   **Authentication:** Required (Admin role)
-   **Query Parameters:**
    -   `skip` (integer, optional): Number of records to skip for pagination.
    -   `limit` (integer, optional): Maximum number of records to return.
    -   `action` (string, optional): Filter by a specific action (e.g., `login_success`).
    -   `resource_type` (string, optional): Filter by resource type (e.g., `user`).
    -   `user_id` (integer, optional): Filter by user ID.
-   **Responses:**
    -   `200 OK`: A list of audit log entries.
    -   `403 Forbidden`: If the user is not an administrator.

---

#### **Get Audit Statistics**

-   **Endpoint:** `GET /audit/stats`
-   **Description:** Retrieves statistics about audit log events. Restricted to administrators.
-   **Authentication:** Required (Admin role)
-   **Responses:**
    -   `200 OK`: A summary of audit statistics.
    -   `403 Forbidden`: If the user is not an administrator.

---

### Dashboard (`/dashboard`)

Endpoints for retrieving data for the main dashboard.

---

#### **Get Dashboard Statistics**

-   **Endpoint:** `GET /dashboard/stats`
-   **Description:** Retrieves aggregated statistics for the dashboard, including total scans, hosts, ports, and recent activity.
-   **Authentication:** Required (any role)
-   **Responses:**
    -   `200 OK`: A `DashboardStats` object with all the dashboard data.

---

#### **Get Port Statistics**

-   **Endpoint:** `GET /dashboard/port-stats`
-   **Description:** Retrieves statistics about the most common open ports.
-   **Authentication:** Required (any role)
-   **Responses:**
    -   `200 OK`: A list of common ports and their counts.

---

#### **Get OS Statistics**

-   **Endpoint:** `GET /dashboard/os-stats`
-   **Description:** Retrieves statistics about the distribution of operating systems.
-   **Authentication:** Required (any role)
-   **Responses:**
    -   `200 OK`: A list of operating systems and their counts.

---

### DNS (`/dns`)

Endpoints for DNS-related operations.

---

#### **Get DNS Records**

-   **Endpoint:** `GET /dns/records`
-   **Description:** Retrieves stored DNS records for a given hostname.
-   **Authentication:** Required (any role)
-   **Query Parameters:**
    -   `hostname` (string, required): The hostname to query.
-   **Responses:**
    -   `200 OK`: A list of `DNSRecord` objects.

---

#### **Perform DNS Lookup**

-   **Endpoint:** `POST /dns/lookup/{hostname}`
-   **Description:** Performs a live DNS lookup for a hostname and stores the results.
-   **Authentication:** Required (any role)
-   **Path Parameters:**
    -   `hostname` (string, required): The hostname to look up.
-   **Responses:**
    -   `200 OK`: The results of the DNS lookup.

---

### Export (`/export`)

Endpoints for exporting data in various formats.

---

#### **Export Scope Report**

-   **Endpoint:** `GET /export/scope/{scope_id}`
-   **Description:** Exports a comprehensive report for a specific scope.
-   **Authentication:** Required (any role)
-   **Path Parameters:**
    -   `scope_id` (integer, required): The ID of the scope to export.
-   **Query Parameters:**
    -   `format_type` (string, optional): The format of the report (`json`, `csv`, `html`). Defaults to `json`.
-   **Responses:**
    -   `200 OK`: The report file as a download.
    -   `404 Not Found`: If the scope does not exist.

---

### Hosts (`/hosts`)

Endpoints for managing and querying host information.

---

#### **Get Hosts**

-   **Endpoint:** `GET /hosts/`
-   **Description:** Retrieves a list of hosts with powerful filtering capabilities.
-   **Authentication:** Required (any role)
-   **Query Parameters:**
    -   `state` (string, optional): Filter by host state (e.g., `up`, `down`).
    -   `search` (string, optional): A general search term for IPs, hostnames, OS, etc.
    -   `ports` (string, optional): Comma-separated list of ports to filter by.
    -   `services` (string, optional): Comma-separated list of service names.
    -   `port_states` (string, optional): Comma-separated list of port states (e.g., `open`).
    -   `has_open_ports` (boolean, optional): Filter for hosts with at least one open port.
    -   `os_filter` (string, optional): Filter by operating system name.
    -   `subnets` (string, optional): Comma-separated list of subnet CIDRs.
    -   `skip` (integer, optional): For pagination.
    -   `limit` (integer, optional): For pagination.
-   **Responses:**
    -   `200 OK`: A list of `Host` objects.

---

#### **Get Host Details**

-   **Endpoint:** `GET /hosts/{host_id}`
-   **Description:** Retrieves detailed information for a specific host.
-   **Authentication:** Required (any role)
-   **Path Parameters:**
    -   `host_id` (integer, required): The ID of the host.
-   **Responses:**
    -   `200 OK`: A `Host` object.
    -   `404 Not Found`: If the host does not exist.

---

### Risk Assessment (`/risk`)

Endpoints for security risk analysis and vulnerability management.

---

#### **Get Risk Summary**

-   **Endpoint:** `GET /risk/hosts/risk-summary`
-   **Description:** Provides an overall risk summary for the dashboard.
-   **Authentication:** Required (any role)
-   **Responses:**
    -   `200 OK`: A summary of risk statistics.

---

#### **Get High-Risk Hosts**

-   **Endpoint:** `GET /risk/hosts/high-risk`
-   **Description:** Retrieves a list of hosts that are considered high-risk.
-   **Authentication:** Required (any role)
-   **Query Parameters:**
    -   `limit` (integer, optional): The maximum number of hosts to return.
    -   `min_risk_score` (float, optional): The minimum risk score to be considered high-risk.
-   **Responses:**
    -   `200 OK`: A list of high-risk hosts.

---

### Scans (`/scans`)

Endpoints for managing and viewing scan results.

---

#### **Get Scans**

-   **Endpoint:** `GET /scans/`
-   **Description:** Retrieves a list of all imported scans with summary information.
-   **Authentication:** Required (any role)
-   **Query Parameters:**
    -   `skip` (integer, optional): For pagination.
    -   `limit` (integer, optional): For pagination.
-   **Responses:**
    -   `200 OK`: A list of `ScanSummary` objects.

---

#### **Get Scan Details**

-   **Endpoint:** `GET /scans/{scan_id}`
-   **Description:** Retrieves detailed information about a specific scan.
-   **Authentication:** Required (any role)
-   **Path Parameters:**
    -   `scan_id` (integer, required): The ID of the scan.
-   **Responses:**
    -   `200 OK`: A `Scan` object.
    -   `404 Not Found`: If the scan does not exist.

---

### Scopes (`/scopes`)

Endpoints for managing scopes and subnets.

---

#### **Upload Subnet File**

-   **Endpoint:** `POST /scopes/upload-subnets`
-   **Description:** Creates a new scope by uploading a file containing a list of subnets.
-   **Authentication:** Required (any role)
-   **Form Data:**
    -   `scope_name` (string, required): The name for the new scope.
    -   `scope_description` (string, optional): A description for the scope.
    -   `file` (file, required): A `.txt` or `.csv` file with one subnet CIDR per line.
-   **Responses:**
    -   `200 OK`: A confirmation message with the number of subnets added.
    -   `400 Bad Request`: If the scope name already exists or the file is invalid.

---

#### **Get Scopes**

-   **Endpoint:** `GET /scopes/`
-   **Description:** Retrieves a list of all scopes with summary information.
-   **Authentication:** Required (any role)
-   **Responses:**
    -   `200 OK`: A list of `ScopeSummary` objects.

---

### Upload (`/upload`)

Endpoint for uploading scan files.

---

#### **Upload Scan File**

-   **Endpoint:** `POST /upload/`
-   **Description:** Uploads a scan file from various supported tools (Nmap, Masscan, Nessus, etc.). The API will automatically detect the file type and parse it.
-   **Authentication:** Required (any role)
-   **Form Data:**
    -   `file` (file, required): The scan file to upload. Supported extensions: `.xml`, `.json`, `.csv`, `.txt`, `.gnmap`, `.nessus`.
-   **Query Parameters:**
    -   `enrich_dns` (boolean, optional): If `true`, performs DNS enrichment on the discovered hosts.
    -   `dns_server` (string, optional): A custom DNS server to use for enrichment.
-   **Responses:**
    -   `200 OK`: A `FileUploadResponse` object with the status of the upload and the new scan ID.
    -   `400 Bad Request`: If the file type is not supported, the file is too large, or parsing fails.

# User Guide

## 1. Setup and Installation

To set up and run the NetworkMapper application, you need to have Docker and Docker Compose installed on your system.

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd NetworkMapper
    ```

2.  **Start the application:**
    ```bash
    docker-compose up -d
    ```
    This command will build the Docker images for the frontend and backend, start the containers, and run the application in the background.

3.  **Access the application:**
    *   The frontend will be available at `http://localhost:3000`.
    *   The backend API will be available at `http://localhost:8000`.

## 2. Using the Application

The NetworkMapper application allows you to upload and analyze network scan results.

*   **Dashboard:** The dashboard provides a high-level overview of your scans, including statistics on the number of scans, hosts, and open ports.
*   **Scopes:** Before you can analyze your scans, you need to define your network scopes. A scope is a collection of subnets that you want to include in your analysis.
    *   To create a new scope, go to the "Scopes" page and click on "Create Scope".
    *   You can either create an empty scope and add subnets later, or you can upload a file containing a list of subnets (one per line).
*   **Uploading Scans:**
    *   Go to the "Scans" page and click on "Upload Scan".
    *   You can upload Nmap XML files, Masscan XML/JSON/list files, and Eyewitness JSON/CSV reports.
    *   You can also choose to enrich the scan data with DNS information.
*   **Viewing Scan Results:**
    *   After a scan is uploaded, you can view the results by clicking on the scan in the "Scans" list.
    *   The scan detail page shows information about the scan, including the hosts that were found, the open ports, and any out-of-scope findings.
*   **Viewing Host Details:**
    *   You can click on a host to view more details, including the open ports, the operating system, and any scripts that were run against the host.
*   **Exporting Reports:**
    *   You can export reports for a specific scan or scope in JSON, CSV, or HTML format.

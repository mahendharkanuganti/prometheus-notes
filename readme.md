# Prometheus

- [Prometheus](https://github.com/prometheus) is an open-source systems monitoring and alerting toolkit originally built at
[SoundCloud](https://soundcloud.com/).
- Prometheus collects and stores its metrics as time series data, i.e. metrics information is stored with the timestamp at which it was recorded, alongside optional key-value pairs called labels.
- **Features:**
    
    Prometheus's main features are:
    
    - a multi-dimensional [data model](https://prometheus.io/docs/concepts/data_model/) with time series data identified by metric name and key/value pairs
    - PromQL, a [flexible query language](https://prometheus.io/docs/prometheus/latest/querying/basics/) to leverage this dimensionality
    - time series collection happens via a pull model over HTTP
    - [pushing time series](https://prometheus.io/docs/instrumenting/pushing/) is supported via an intermediary gateway
    - targets are discovered via service discovery or static configuration
    - multiple modes of graphing and dashboarding support
    

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3700de77-8e42-4c16-8174-1a8372456e9b/fd517f78-062f-4571-a1b6-9b8047bf9210/Untitled.png)

- **Simple understandable architecture:**
    
    ![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3700de77-8e42-4c16-8174-1a8372456e9b/6145039e-7c56-4f56-9e04-acec9ef32d73/Untitled.png)
    

### 2 types of monitoring:

1. Black box monitoring
2. White box monitoring
- Black box monitoring:
    1. End users, means us, we can test the apps, like whether its logging in or not, if our posts are publishing or not in social media apps, this kind of tests we can test/monitor as end users.
- White box monitoring:
    1. Application internal Monitoring. This will be monitored only by internal facebook team or any other company team.
    2. Example:
        1. Server CPU, RAM, Memory
        2. Number of requests
        3. Latency: Time taken to respond our requests
        4. Logs monitoring.
- There are 4 golden signals are for good application monitoring. which we will follow these in ELK stack.
    1. Latency
    2. Traffic
    3. Memory
    4. Errors

### Example of Prometheus:

- CCTV:
    1. CC cameras
    2. centralized monitors
    - cc cameras are used for capturing videos, and centralized system is pulling those videos.
        1. Live/Instant video
        2. Historical
- Pull & Push
    - pull model will have agents
    - push model will not have agents
    - Prometheus is pull model monitoring.
    - we need to install the node_exporter agent in nodes.
    so that way Prometheus will fetch the data from nodes every 5 or 10 seconds (as we configure.)
- Time Series Database:
    - whatever the data we collect with proper date and times that is called time series database.
        - 29-JUL 500
        30-JUL 600
        31-JUL 499
            
            quarterly, yearly, weekly
            
        - Prometheus will fetch the data from nodes and store them in the time series database.
        - If a user accesses Prometheus with HTTP, then HTTP will access the time series database and show the content to the user.

### Steps to download and install Prometheus:

1. Create EC2 instance as Prometheus
2. Login to EC2
`cd /opt`
3. Download the prometheus for Linux from official site: [`https://prometheus.io/download`](https://prometheus.io/download)
    
    ```bash
    wget https://github.com/prometheus/prometheus/releases/download/v2.54.0-rc.0/prometheus-2.54.0-rc.0.linux-amd64.tar.gz
    ```
    
4. extract the prometheus tar file
    
    ```bash
    tar -xvzf prometheus-2.54.0-rc.0.linux-amd64.tar.gz
    ```
    
5. Rename the prometheus file with any short name, just for convenience.
    
    ```bash
    mv prometheus-2.54.0-rc.0.linux-amd64 prometheus 
    ```
    
6. Create systemd unit file (service file) for prometheus
    
    ```bash
    # vim /etc/systemd/system/prometheus.service
    [Unit]
    Description=Prometheus Server
    Documentation=https://prometheus.io/docs/introduction/overview/
    After=network-online.target
        
    [Service]
    Restart=on-failure
    ExecStart=/opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml
    
    [Install]
    WantedBy=multi-user.target
    ```
    
7. start and enable prometheus service. then check status.
8. `netstat -lntp`  - Prometheus will open 9090 port.
    
    ```bash
    [ root@ip-172-31-32-21 /opt/prometheus ]# netstat -lntp
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1245/sshd: /usr/sbi
    **tcp6       0      0 :::9090                 :::*                    LISTEN      1605/prometheus**
    tcp6       0      0 :::22                   :::*                    LISTEN      1245/sshd: /usr/sbi
    
    52.87.208.118 | 172.31.32.21 | t2.micro | null
    [ root@ip-172-31-32-21 /opt/prometheus ]#
    
    ```
    
9. Allow the port 9090 in prometheus EC2 instance’s security group.
10. Take public IP of EC2 and open prometheus in browser.
http://<pub-IP>:9090

- prometheus will monitor itself as well as other nodes too. meaning the same localhost it will monitor.
    - up - instant data
    - up[1m] - historical data >> last 1 minute data
    - Refer below article for PromoQL cheatSheet.
        - [`https://promlabs.com/promql-cheat-sheet/`](https://promlabs.com/promql-cheat-sheet/)
- scrape_interval:  to mention the details like, which node to monitor, how frequently (5s, 15, 1m) it should monitor, which job and other options
    
    ```bash
    #prometheus.yaml
    # my global config
    global:
      scrape_interval: 15s # Set the scrape interval to every 15 seconds. Default is every 1 minute.
      evaluation_interval: 15s # Evaluate rules every 15 seconds. The default is every 1 minute.
      # scrape_timeout is set to the global default (10s).
    ```
    
- if you click on globe symbol option in prometheus UI, you can see all monitoring options.
- in GUI > status > configuration - we can see all its configuration data.

### Configure a node to get monitored by prometheus:

1. Create 2 EC2 nodes
2. login to it
3. download and install node_exporter from prometheus page [Download | Prometheus](https://prometheus.io/download/)
    
    `cd /opt`
    
    `https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz`
    
4. extract and rename to a short name node_exporter, just for convenience.
5. `cd node_exporter`
you will see `node_exporter` here, this `node_exporter` software/tool runs in nodes and collect all the data. then `node_exporter` will provide the data to prometheus when it asks.
or it will also collect when prometheus asks to collect.
6. Rather running the `node_exporter` directly, we will run it from the service.
7. create node_exporter service file.
    
    ```bash
    # vim /etc/systemd/system/node_exporter.service
    [Unit]
    Description=Node Exporter
    After=network-online.target
    
    [Service]
    Restart=on-failure
    ExecStart=/opt/node_exporter/node_exporter
    
    [Install]
    WantedBy=multi-user.target
    ```
    
8. Start and enable node_exporter service
    
    ```bash
    systemctl daemon-reload
    systemctl start node_exporter
    systemctl enable node_exporter
    systemctl status node_exporter
    ```
    
9. `netstat -lntp`  - node_exporter runs on 9100 port.
10. Add a new job for nodes in prometheus config file. so that it will monitor the nodes.
    
    ```bash
    #prometheus.yaml
    scrape_configs:
      # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
      - job_name: "prometheus"
    
        # metrics_path defaults to '/metrics'
        # scheme defaults to 'http'.
    
        static_configs:
          - targets: ["localhost:9090"]
            labels:
              name: prometheus
    
      - job_name: "nodes"
        static_configs:
          - targets: ["172.31.43.191:9100"]
            labels:
              name: node-1
    ```
    
11. Restart the prometheus service.
    
    ```bash
    systemctl start prometheus
    ```
    
12. check the logs `less /var/log/messages` 
    1. it will load config file and get ready for receiving metrices.
13. now check in prometheus UI, you will see node there and its status as well.
    1. you can query it by `up` `up[1m]` etc.
14. for test purpose, shutdown the node and check the status again in prometheus.

### Steps to install grafana:

1. Go to official grafana documentation > Docs > opensource > grafana > Install on linux option > select RHEL from left
    
    ```bash
    wget -q -O gpg.key https://rpm.grafana.com/gpg.key
    	# Ig gpgkey is not downloading, then open the URL in browser and then create a file with gpg.key name in server level.
    sudo rpm --import gpg.key
    ```
    
2. Create /etc/yum.repos.d/grafana.repo with the following content:
    
    ```bash
    [grafana]
    name=grafana
    baseurl=https://rpm.grafana.com
    repo_gpgcheck=1
    enabled=1
    gpgcheck=1
    gpgkey=https://rpm.grafana.com/gpg.key
    sslverify=1
    sslcacert=/etc/pki/tls/certs/ca-bundle.crt
    ```
    
3. install Grafana:
    
    ```bash
    sudo dnf install grafana
    ```
    
4. Complete the following steps to start the Grafana server using systemd and verify that it is running.
    
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl start grafana-server
    sudo systemctl status grafana-server
    sudo systemctl enable grafana-server.service
    ```
    
5. `netstat -lntp` - Grafana runs on port 3000.

**Note:** For Grafana, no need to create the systemd service file.

**Note**: we have installed grafana in prometheus server itself. So, we have to use the prometheus server public Ip itself to connect to grafana.

1. Take the public IP of prometheus and browse it with 3000 port for grafana.
    
    ```bash
    http://<public-IP-of-prometheus-server>:3000
    
    username: admin
    pwd: admin
    give new pwd: anything
    ```
    
2. In Grafana UI, do the following to add prometheus as connection.
    1. Go to connections > Add new connection > search for prometheus and select > add new data source > enter prometheus server URL > give localhost URL [`http://localhost:9090`](http://localhost:9090/) > save and test.
    2. Grafana is taking the data as input from prometheus localhost
3. Follow below steps in grafana to create a dashboard.
    1. Dashboards > create dashboard > add visualization > prometheus > click code > and give query `up` > or `up[1m]` > Now explore the options. > save it
        
        This will create a dashboard in grafana.
        
- In Realtime environment also, we can install prometheus and grafana in the same server. So, there will be no latency and it helps to speed up the data fetch.
- If there are any opensource grafana dashboards, we can import them using the dashboard ID(1235 or 78612 etc. any 4 or 5 digit ID).

### Service Discovery:

- Service discovery component helps to find the newly automatically created VM’s (part of auto-scaling & replicasets) and add them to node monitoring in prometheus.
- prometheus should find the nodes automatically using service-discovery and add them to scrape list.
    - scrape means - list of nodes details to be monitored.
- The underlying nodes should have node_exporter installed and started.
- To find the EC2 instances automatically, prometheus will describe the EC2 instances for details and get the IP and other details.
- So, prometheus server should have the describe permission in AWS.
    - In AWS, Go to IAM > create role > give role name
    - Go to policy > create policy > EC2 > describe instances > provide name for policy.
    - Go to role > attach newly created EC2 describe policy here.
    - Go to prometheus EC2 in AWS > actions > security > modify IAM role > choose the new role we created
- If the monitoring tag is set to true for an ec2, then prometheus will enable the monitoring for that ec2.
    - Go to EC2 > Tag > Monitoring: true # set the monitoring tag to true
    
    ```bash
    **example:**
      - job_name: "ec2_sd"
    	ec2_sd_configs:
        - region: eu-east-1
    	  port: 9100
    	  filters:
    	    - name: tag:Monitoring
    		  values:
    		    - true
    	  relabel_configs:
            - source_labels: [__meta_ec2_instance_id]
    					target_label: instance_id
    				- source_labels: [__meta_ec2_private_ip]
    					target_label: private_ip
    				- source_labels: [__meta_ec2_tag_name]
    				  target_label: name
    ```
    

### Alerting Mechanism:

- Alerting with Prometheus is separated into two parts. Alerting rules in Prometheus servers send alerts to an Alertmanager. The [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) then manages those alerts, including silencing, inhibition, aggregation and sending out notifications via methods such as email, on-call notification systems, and chat platforms.
- The main steps to setting up alerting and notifications are:
    - Setup and [configure](https://prometheus.io/docs/alerting/latest/configuration/) the Alertmanager
    - [Configure Prometheus](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alertmanager_config) to talk to the Alertmanager
    - Create [alerting rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/) in Prometheus
    - we have to configure the rules for alert mechanism under prometheus configuration file
- Below the example Alerting rule to create alert for instance down events
    
    ```bash
    # vim instancedown.yaml
    
    groups:
    - name: InstanceDown
      rules:
      - alert: InstanceDownalert
        expr: up < 1     # up < 1 - meaning 0 - so if system is down. it will create active alert.
        for: 1m          # frquency to monitor the nodes
        labels:
          severity: critical  # severity levels are critical, warning, error, info
        annotations:
          summary: Instance is down
    ```
    
- Now configure the prometheus configuration file to read these alerting file
    
    ```bash
    # Load rules once and periodically evaluate them according to the global 'evaluation_interval'.
    rule_files:
      - "alert_rule/*.yaml"		#it will fetch all the alrting rules under `alert_rule` directory.
      # - "second_rules.yml"
    ```
    
- restart the prometheus service and check in the prometheus UI > Alerts > you will see alert is raised. (make sure you check all check boxes).
- **Installing and configuring Alertmanager:**
    1. Go to prometheus official documentation `https://prometheus.io/download/`
    2. `cd /opt`
    3. download the alert manager in Prometheus EC2
        
        ```bash
        wget https://github.com/prometheus/alertmanager/releases/download/v0.27.0/alertmanager-0.27.0.linux-amd64.tar.gz
        ```
        
    4. Extract the alertmanager tar file.
        
        ```bash
        tar -xvzf alertmanager-0.27.0.linux-amd64.tar.gz
        ```
        
    5. Rename the file
        
        ```bash
        mv alertmanager-0.27.0.linux-amd64 alertmanager
        ```
        
    6. Create alertmanager service file
        
        ```bash
        #vim /etc/systemd/system/alertmanager.service
        
        [Unit]
        Description=Alertmanager
        Wants=network-online.target
        After=network-online.target
        
        [Service]
        Type=simple
        WorkingDirectory=/opt/alertmanager/
        ExecStart=/opt/alertmanager/alertmanager --config.file=/opt/alertmanager/alertmanager.yml
        
        [Install]
        WantedBy=multi-user.target
        ```
        
    7. Configure the `alertmanager.yaml` file with your email and smtp endpoint details
        1. in AWS > SES > create Identity with your email address > then verify it from Gmail 
        2. Goto SMTP settings > create SMTP credentials > create user > note down username and password
        
        ```bash
        route:
          group_by: ['alertname']
          group_wait: 30s
          group_interval: 5m
          repeat_interval: 1h
          receiver: 'ses'
        receivers:
          - name: 'ses'
            email_configs:
              - smarthost: email-smtp.us-east-1.amazonaws.com:587    #this SMTP endpoint is same for all AWS user
                auth_username: your-username   #change the SMTP username
                auth_password: your-password   #change the SMTP password
                from: your-from-address        #add your from email
                to: your-to-address
                headers:
                  subject: Prometheus Mail Alert
        inhibit_rules:
          - source_match:
              severity: 'critical'
            target_match:
              severity: 'warning'
            equal: ['alertname', 'dev', 'instance']
        ```
        
    8. restart the service
        
        ```bash
        systemctl daemon-reload
        systemctl start alertmanager
        systemctl enable alertmanager
        systemctl status alertmanager
        ```
        
    9. `netstat -lntp`  - alertmanager runs on port  9093/9094
    10. Now go to `prometheus.yaml` and add configure it with alertmanager.
        
        ```bash
        # Alertmanager configuration
        alerting:
          alertmanagers:
            - static_configs:
                - targets:
                  - localhost:9093
        ```
        
    11. Restart the prometheus service.
        
        ```bash
        systemctl restart prometheus
        systemctl status prometheus
        ```
        
    12. Go to prometheus > Alerts > and check if the active alert is `fired`
    13. Once the alert status is `fired` in prometheus, Go to browser with prometheus server public IP address http://<ip>:9093  `9093 port for alertmanager UI`
        1. because alertmanager should be installed in prometheus server itself
    14. Check in alertmanager UI to see if you received that alert.
        1. we must have received email to our gmail from alertmanager.

### ELK (Elastic Logstash Kibana):

- ELK is a powerful set of tools used for searching, analyzing, and visualizing large volumes of data in real-time. The acronym ELK stands for Elasticsearch, Logstash, and Kibana.
    1. **Elasticsearch**:
        - **Purpose**: It is a search and analytics engine.
        - **Function**: Stores data and allows you to search and analyze it quickly and in real-time.
            - Elasticsearch is a like a repository which holds/stores data, logs etc.
        - **Key Feature**: It's highly scalable and can handle large amounts of data.
    2. **Logstash**:
        1. Logstash will filter/stash the logs and convert into the format we want and then send the logs to elasticsearch.
        2. it will filter the logs and also convert the semi-structured/unstructured logs into structured logs as per our needs.
        3. It is better to have elasticsearch and Kibana in the same server.
        - **Purpose**: It is a data processing pipeline.
        - **Function**: Collects, processes, and forwards data.
        - **Key Feature**: Can take data from multiple sources, transform it, and send it to Elasticsearch (or other destinations).
    3. **Kibana**:
        1. Kibana will query the logs and provide the visualization.
        - **Purpose**: It is a visualization tool.
        - **Function**: Allows you to create and share dynamic dashboards based on the data stored in Elasticsearch.
        - **Key Feature**: Provides powerful charts and graphs to visualize data insights.
- **Creation of resources for ELK:**
    1. create and EC2 instance name it as ELK
        1. follow this steps for installing all the below resources:
            1. create Ec2 for ELK then follow these steps as in this URL https://github.com/daws-78s/concepts/blob/main/elk.MD
        2. in ELK Ec2, install below resources:
            1. Elasticsearch
            2. Logstash
            3. kibana
    2. Once above steps are done, Create EC2 instance and name it as frontend.
        1. run the frontend shell script from `expense-shell` git repo.
        2. access the web UI with public IP and give multiple clicks to generate the logs.
        3. Install filebeat in frontend server
- Generally, the web application logs, or any other logs are unstructured/semi-structured. So, to make them structured logs use filebeat agent to send the logs data to elasticsearch and kibana will filter them and give us the structured data.
- Filebeat:
    - install filebeat in the frontend server, meaning in which server the application logs we want to monitor they should have filebeat agent installed. (just like crowdstrike, tanium, node_exporter etc..)
    - Now go to elasticsearch/kibana UI > Discover > stack management > index management > Index pattern > give any name > @timestamp > save
    - developers will check the logs in kibana
    - so in this case, filebeat sends to logs to logstash first to filter and format and then to elasticsearch.
    - check in the logs messages of frontend, that if filebeat is connected to elasticsearch and sent the logs.
    - for filebeat, application logs are input, and it sends those logs to elasticsearch as output.
    - filebeat access the logs and push to elasticsearch
    - mostly all the logs are semi-structured. only DB is structured.
    - to see how logs are structured, check in its config file.
    - each line stored in logs (/var/log/messages) will be pushed to elasticsearch UI, there we can see the logs count.
- in elasticsearch UI, index is nothing but getting the data ready for visualization.
- Filter:
    - input - filter(logstash) - output
    - in between input and output we have 'filter'.
    - so to filter the data we need to use grok patters.
    - go to nginx config file and change the log format with grok pattern
    - sample logstash:
        
        ```bash
        input {									<< filter will take the input from here
          beats {
            port => 5044
          }
        }
        filter {								<< filter and format the data as per needs
              grok {
                match => { "message" => "%{IP:client_ip} \[%{HTTPDATE:timestamp}\] %{WORD:http_method} %{URIPATH:request_path} %{NOTSPACE:http_version} %{NUMBER:status:int} %{NUMBER:response_size:int} \"%{URI:referrer}\" %{NUMBER:response_time:float}" }
              }
        }
        output {								<< send the filtered data to elasticsearch.
          elasticsearch {
            hosts => ["http://localhost:9200"]
            index => "%{[@metadata][beat]}-%{[@metadata][version]}"
          }
        }
        ```
        
- once logstash config is done, generate few logs from frontend expense app by giving just clicks.
- you can see them in elasticsearch UI in logs.
- so now you can create visualization for that logs
    - In elasticsearch UI > analytics > visualization > visualization library > create visualization > lens.
    - now give values in vertical axis and horizontal axis as per requirement.
    then save it as a new dashboard.
- **Interview purpose:**
- what you do for elasticsearch:
    - We install filebeat, elasticsearch, kilogstash in servers then we send the logs/data to logstash.
    - ELK team also works closely with us so we have an understanding of stashing using grok patterns in logstash, these filtered logstashed data will go to elasticsearch and there we use visualizations.
    - we also have access to dashboard. we monitor on latency, errors, traffic in dashboard

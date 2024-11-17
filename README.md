# Overview
The Identity Plus mTLS Gateway is a reference implementation of the Identity Plus mTLS based Identity & Access Control solution. While the more familiar terminology in the field is Identity & Access Management, the choice of words here is not accidental. While industry solutions (the ones we call IAM) focus on managing indentities so that control systems can be effective, the Identity Plus IaC Solution eliminates the management problem to deliver simple, granular and highly scalable mutual TLS based access control.

This refernce implementation offers an easy entry into our groundbraking fusion of a self asserted identity model with mutual TLS based access control, which offers a radical improvment in security by eliminating 99.99999% of the surface of attack at a fraction of today's expenditure, both in terms of cost and effort.

## Requirements

- A small VPC in any cloud environment. This can be substituted with a Docker environment on a single (potentially local machine)
- A LAN defined within the VPC (or inside the Docker environemnt) that connects instances (VMs or containers) within the enviornment
- We are going to be working with 3 VMs (for testing purposes any configuration will do, 512MB - 1GB of RAM, 1-2 vCPUs, 30GB disk space). Most of this capacity is needed to support the Linux envioronment on which the demo will run, so please calibrate your needs to that
- The demo is based on x86 64bit architecture, so for simplicity we recommend using that. The demo can be adapted to other architectures by modifying docker base image URLs. We recommend doing that after gaining some experience.
- Each VM will have to be connected to the LAN, and one VM (the one hosting the mTLS Gateway) should be attached a public IP as well
- If a Load Balancer (ALB, ELB, or any cloud load balancer) is configured in front of the mTLS Gateway, please make sure the balancing is at TCP layer (not HTTP). The mTLS Gateway must own the TLS offloading process. Mutual TLS connections cannot be man-in-the-middled (it is the way they are supposed to be) so if there is a proxy offloading and re-ncapsulating the communication between the client and the mTLS Gateway, the "m" part of the TLS will be lost and client certificate authentication will fail.

## Installation Steps

### 1. Sign up for a DIGITAL IDENTITY on Identity Plus

From an IDENTITY perspective, Identy Plus is a Self Asserted Digital Identity Service which gives you the ability to become the Certificate Authority for your own devices - both as an individual or as a service (part of an organization) - a process we call Self-Authority. This will give you, and anyone in the system, the ability to issue client certificates that associated to their identity to be used in the interest of establishing mTLS connection (TLS authenticated conne connections). 

Signing up for an Idnetity Plus Digital Identity (we don't call them accounts) essentially means issuing your first client certificate for, your first end-user device. Go to https://signon.identity.plus and follow the steps. Once the certificate is installed you may have to restart your browser (sometimes an incognito window is sufficient). This happens because browsers are caching TLS sessions and do not immediately pick up the client certificate. This technique is not standardized so your experience may vary depending on your OS and your browser. The process is successful when you are able to login into https://my.identity.plus, using the previousely installed client certifcate.

### 2. Create your first organizations

After step 1 is completed and you are able to log into your Identity Plus account, follow the link to https://platform.identity.plus. You will have no organizations at this point, so follow the clues. Chose Personal plan for development and testing purpose stuff and give your organization a name.

Please chose your organization id well. This is important because your organization will be assigned a subdomain trunk in the .mtls.app domain, like your-org-id.mtls.app, which will be unique to your organization. All of your serivces under that organization will be assigned subdomains in this subdomain trunk. The organization id can be change later, but it may imply a lot of work, because all service domains will be changed and server certificates will need to be re-issued.

### 3. Creating the five services

Once your organization is created we will configure four services in the Identity Plus platform, the three internal, VPC based services, and one that we will use as a mock service to serve as a 3rd Party service for testing purposes. This one will not require a deployment, but we do need it for administrative (management) purposes.

As a notem from a naming perspective, like with the organization, these services can in principle be named any way, and the name can be changed later, with less work than the organization but still some administrative overhead. For ease of the process, let's use the service names specified in this documentation, simply beacuse the deployment config files are pre-configured with those names and so we eliminate some complexity during the testing. Service names need not be unique world-wide, only organization wide, because each service id will be suffixed with the .your-org.mtls.app subdomain which will give it a unique glabal uri (identitifier).

An important note is that while the Gateway will require a machine to run on, it does not require a dedicated service in Indentity Plus. The Gateway offers means to services to be mTLS Gated (routed), and each routed service has its own slice on the Gateway and that slice is configured with access control dedicated to that service in particular. 

Below is a short schematic representaion of the demo environment. 
1. Domain names represent services and their access proints via the reverse proxy.
2. Client VM is accessing service via the Gateway (managed proxy with mTLS RBAC (role based access control) validation
3. We are not using more machines as access is network idnependent (both internal and external work exactly the same, the solution is 100% portable across TCP/IP networks)
4. Gateway admin access will be managing the 

```

                                   +-------- mgmt ---------+
                                   |                       |
                   +---------------|------------------+    |                  +--------------------+
                   | minio.your-org.mtls.app:443 ----------|--------------->  | minio:9001 (admin) |
   +------------>  | minio.your-org.mtls.app:444 ----------+                  |                    |
   |  +--------->  | minio-api.your-org.mtls.app:443 ---------------------->  | minio:9000 (API)   |
   |  |            | minio-api.your-org.mtls.app:444 -- - mgmt -              +--------------------+
   |  |            | pg.your-org.mtls.app:5432 ----------------+                MinIO VM ^^
   |  |            | pg.your-org.mtls.app:444 -- - mgmt -      |                 
   |  |            +----------------------------------+        |              +--------------------+
   |  |              Gateway VM ^^                             +----------->  | postgres:5432      |
   |  |                                                                       +--------------------+  
   |  |                                                                         Postgres VM ^^
   |  |                          
   |  |                                                              +--------------+
   |  +---------------------- controlled access -------------------- | Client       |
   |                                                                 +--------------+
   |                                                                   Client VM ^^
   |
   |                                            +--------------------+
   +-------------- admin ---------------------- | Gateway Admin      |
                                                +--------------------+
                                                  Browser ^^

```

#### 3.1 The MINIO Object Storage Service - Admin Service

As a side note, technically speaking the MINIO Object Storage Service has two interfaces (the Admin and the API), which require differnt access control criteria and for that alone it makes sense to treat them as separate services. They do run on different ports too, so this makes routing (proxying) easier also.  

Side note closed, in the "Services" page, under "Your Organization" let's click "Create Service" and give it the name "Minio".

Once created, let's enter the service, and in the "Identity" menu, "Display Name" section, let's change the name to "Minio Admin", for better clarity. Please also note that "Identity & Ownership" section, the unique name of the service will be minio.your-org.mtls.app. This is a true domain name, allocated to your service the DNS record table of which can be configured - we'll do that shortly.

#### 3.2 The MINIO Object Storage Service - API Service

Following the pattern in 4.1, let's just name it "Minio API". Also nothe that by by doing so, the minio-api.your-org.mtls.app domain name will be allocated to it by default.

#### 3.3 Creating Postgres DB Service

Following the patter in 4.1, let's just name it "pg" and then edit the "Display Name" section as above to show "Postgres DB Service". as a result we will have a nice explicit name and a short and weet domain pg.your-org.mtls.app.

The reason we are configuring a Postgres service is because the mTLS Gateway can route plain TCP connection over mTLS too, not just HTTPS communcation.

#### 3.3 Creating "Internal Client" service

Following the patter in 4.1, let's just name it "int". Also, let's just use the "Internal Client" display name for it.

#### 3.4 Creating "3rd Party Client" service

Following the patter in 4.1, let's just name it "ext", and use the "3rd Party Client" for easier identification.

### 4. Deploying the Servers

In this root of this repository there is a directory called "demo" and in it, you can find 3 shell scripts, which, let's use those to provision the VMs. The scripts can be used as cloud init scripts or simply to run them after. We will deploy 4 VMs using the three scripts:

* Gateway: containing the mTLS Gateway service running inside a docker environment. This mush be accessible from the Internet if you wish to test across the Internet
* Minio: whch will contain both the MINIO Admin and the MINIO API service running on ports 9001 and 9000 respectively
* Postgres: which will host the PostgreSQL Database service, also inside a dokcer environment exposed internally on port 5432 (standard)
* Client: which will simply be a test machine, so there is no pre configuration defined for it.

### 5. Service Discovery

Identity Plus relies on Intenet standard, DNS based service naming and discovery, so it can be plugged in seamlessly into any internal or public internal/Internet or mixed environment. The domain names we configured earlier are public domain names, resolvable from anywhere in the world, once configured, which is what we need to do at this step, now that we have the services configured and the VMs demplyed (we know their IP addresses).

We will do the following for each service:

1. Go to https://platform.identity.plus,
2. Select the organization and then each service one-by-one
3. Select the DNS menu
4. add an empty record to point to the public IP address of the Gateway VM. This will make the root of the service (for example, minio.your-org.mtls.app) point to the gateway. We do this because we will be accessing all services via the mTLS gateway. The rest of the service don't need to have a public IP address.
5. add a wildcard (*) record to point to the LAN IP address of each machine. This will make machines resolvable within the LAN. For example, worker.minio.your-org.mtls.app will point internally to the Minio VM. As a side-note, we will point both minio-api and minio to the same VM, because they run on the same VM. This does not constitute a naming/discovery conflict.

### 6. Firewall Access Control

Please make sure the Gatewar service is reachable across the Internet, in most cloud platforms this will not happen by default. For the setup to work, we need four rules:
1. Open port 443 to the world on the Gatway public IP address: clients will use this to consume https backend services
2. Open port 5432 to the world on the Gatway public IP address: clients will use this port to consume TCP prosgres communiaction wrapped in mTLS
3. Open port 444 to the world on the Gatway public IP address: this will be used as an admin consloe for the Gateway once the gateway is initialized (at least one service is configured and mTLS can be enabled)
4. Open port 80 termporarily, preferably for your exit IP alone on the Gatway public IP address: this is necessary to initialize the Gateway. Since we don't have a domain or a certificate on the Gateway at this stage we cannot have mTLS so we will use the initialization service. This service will no longer start if there are configured services, nevertheless, once configured, it is a good idea to just close port 80 from the firewall.

### 7. Trust the Identity Plus Root CA

For a bit of clarity, there are two types of certificates at play when it comes to mTLS:
1. The server certificate, in other words the certificate the server authenticates with, which is most people are used to when it comes to certificates because it is indispensable when it comes to HTTPS
2. The client certificate, in other words the certificate the cliente authenticates with, and which is required on the client end to transform single side TLS into mutual TLS connections

As an IDENTITY service, Identity Plus enables you to become a self authority with primary scope in the client certificate space. This is funamentally novel and unique in the industry - you will not find it anywhere at the time of writing. The certificates you issue operate seamlessly with any client enviornment as they obey the industry standard. Once installed, these client side certificates, which we call mTLS IDs - per the function they serve - operate as machine identities and allow the machine to authenticate on the owner's behalf and establish mTLS connections.

For the service end, the Identity Plus ACCESS CONTROLL component, also works with certificates issued by public certificate authorities - the multitude of service issuing certificates the traditional way. In public deployments where browsers or other third party clients are used the behavior of which is difficult to control, we recommend using the public service providers. At this point it is easier due to the very complicated process of indirect trust in TLS - the public certificate trust ecosystem - in which the Identity Plus Root CA is not yet trusted. While indispensable in the B2C space, this trust ecosystem comes with several limitations and significant added friction when it comes to internal and other explicit (direct) trust use-cases. For example, public CAs will not issue certificates for internal domains, which means you will not be able to use certificates on the server side, unless you purchase a domain and register it for internal purposes, but even then there are limitations. So for local development, internal use-cases, service meshes, corporate use-cases, and other situatuation (even b2b) when it is recommended to explicitly trust the server certificate and not rely on indirect (public) trust system - we recommend using Identity Plus server certificates. From a security perspective they are just strong (if not stronger - due to the direct trust mechanis), they are more convenient and scalable to use (as we offer full automation), and since certs need to be truste any way explicitly, they do not come with any additional inconvenience, aside from the fact that for development purposes you also have to trust them explicitly in your browser.

To do so, please go into any of your services at https://platform.identity.plus, in the "Server Profile" menu, find the "Root Certificate For Browsers" button and download the CA Certificate. Open the browser settings, type "Certificates" in the search bar and open the Certificate Management windo, or KeyCahin in on Mac. find  

### 8. Configuring the Gateway

As a summary, at this point we must have:
1. The VMs deployed, including the mTLS Gateway
2. Services configured in the Identity Plus Platform
3. Naming and discover is configured in Indentity Plus Platfrom to route correctly to the public IP address of the mTLS Gateway (you can test this with a nslookup minio.your-org.mtls.app)
4. Firewall is open and routing to the mTLS Gateway
5. Your browser has an mTLS ID (a client certificate from Identity Plus)
6. Your browser trusts the Identity Plus Root CA for server certificates (This will be necessary becasue the Gatweay will be provisioned with Identity Plus server certificates for convenience)

With the above list checked, follow these stepst to provision the first mTLS protected route on the Gateway:
1. Open the browser and go to http://gateway-public-ip. This service will only be started if the Gateway is in an uninitialized state, meaning it has no domains, no service, nothing associated, so it cannot have certificates as identity since it does not know what/who it is.
2. If all is correctly configured an initialization page will appear asking for an "Autoprovisioning Token" - a one time token that will allow the Gateway to bind itself to an Identity Plus service and ask for both client and server certificates.
3. You can obtain an autoprovisioning token at https://platform.identity.plus, in the "Service Agents" menu. These are the client agents representing services and they need client certificates to authenticate into thirdy party systems, including Identity Plus. The autoprovisioning token will enable the Gateway to enroll an agent into a service to act on its behalf.
4. Let's choose the minio service, grab an autoprovisioning token and paste it into the initialization field on the Gatewy. Press "Provision"
5. Once the service route is provisioned, follow the link (button) to swithch to the secure mode.

From this moment on, the Gatweak will only work over mTLS. You can swap between the services that are provisioned on the gateway and you can use any of them to provision a new route (for a new service) by using a token for that service 

6. This initialization step will have to be repeated for all services: minio-api.your-org.mtls.app, pg.your-org.mtls.app and you can later extend the system with other services if you like.

### 9. Configuring RBAC via the Gateway

To configure Role Bases Access Control for upstream services we need to say a few words first about how the Gateway works.

#### 9.1 Management, Validation & Routing

Under the hood, the mTLS Gateway is in fact a collection of services:

1. The initialization servive, which we already used, running on port http/80 when the Gateway is in an uninitialized state
2. The management service, which we access on port 444 and provides means to easily configure routing and access criteria for upstream services
3. A production ready Nginx revers proxy, with Lua scripting capabilities bundeld as part of the Openresty project: https://openresty.org
4. A validation service, which performs certificate validations and queries against Indentity Plus. Practically, this is the Identity Plus integration peiece, the rest is regular proxy related concepts, which will be present in pretty much any server environment.

We will skip over the initialization service as this is only a helper service and we already talked about it. For the rest of the services we will continue with a little schematic representation and after that individual descriptions::

```

                                                        +---------------+
                                                        | Identity Plus |
                                                        +---------------+
                                                             /|\ |
                                                              |  |
                                                              |  | get identity info and
                                                              |  | access rules from the source
                                                              |  |
                                                              | \|/
                                                    +---------------------+
                                                    | Validation Service  |
                                                    +---------------------+
                                                       /|\ |      /|\ |
                                                        |  |       |  |
                                                        |  |       |  |
                                          +-------------------+    |  |
---------- management request --------->  |  Manager Service  |    |  | get identity info and 
                                          +-------------------+    |  | access rules from local cache
                                                        |          |  |
                                       configer/reload  |          |  |
                                                        |          |  |
                                                       \|/         | \|/
                                                    +--------------------+                                                  +--------------------+
----------------- service request --------------->  |  Nginx / Openresy  |  --------------- route (if allowd) ----------->  |  Upstream Service  |
                                                    +--------------------+                                                  +--------------------+
                                                                      |
                                                                      | deny (if not allowed)
                                                                      | 
                                                                     \|/
                                                               +---------------+
                                                               |   Black Hole  |
                                                               +---------------+


```



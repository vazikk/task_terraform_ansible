# task_terraform_ansible

Написал конфиг terraform: <br>

main.tf <br>

```
provider "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
  region     = var.aws_region
}

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
  tags       = { Name = "main" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "main" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public1_sub_cide
  availability_zone       = var.AZ-1
  map_public_ip_on_launch = true
  tags                    = { Name = "public" }
}

resource "aws_subnet" "public2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public2_sub_cide
  availability_zone       = var.AZ-2
  map_public_ip_on_launch = true
  tags                    = { Name = "public2" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  
  tags = {
    Name = "nat-gateway"
  }
  
  depends_on = [aws_internet_gateway.main]
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.priv_sub_cide
  availability_zone = var.AZ-1
  tags              = { Name = "private" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = var.cidr-0
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "public" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = var.cidr-0
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "private" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.public2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# Security Groups
resource "aws_security_group" "vpn" {
  name   = "vpn"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.cidr-0]
  }

  ingress {
    from_port   = 1194
    to_port     = 1194
    protocol    = "udp"
    cidr_blocks = [var.cidr-0]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "vpn" }
}

resource "aws_security_group" "private" {
  name   = "private"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.vpn.id]
  }

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "private" }
}

resource "aws_security_group" "alb" {
  name   = "alb"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.cidr-0]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "alb" }
}

resource "aws_instance" "vpn" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.vpn.id]
  key_name               = "taski" # ПОМЕНЯЙ НА СВОЙ КЛЮЧ


  tags = { Name = "vpn" }
}

resource "aws_instance" "private" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.private.id]
  key_name               = "taski" # ПОМЕНЯЙ НА СВОЙ КЛЮЧ

  tags = { Name = "private" }
}

# ALB
resource "aws_lb" "main" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public.id, aws_subnet.public2.id]
  tags               = { Name = "main-alb" }
}

resource "aws_lb_target_group" "nginx" {
  name     = "nginx-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check { path = "/" }
}

resource "aws_lb_target_group" "grafana" {
  name     = "grafana-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check { path = "/api/health" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nginx.arn
  }
}

resource "aws_lb_target_group_attachment" "nginx" {
  target_group_arn = aws_lb_target_group.nginx.arn
  target_id        = aws_instance.private.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "grafana" {
  target_group_arn = aws_lb_target_group.grafana.arn
  target_id        = aws_instance.private.id
  port             = 3000
}
```
<br>

variables.tf: <br>

```
variable "aws_access_key" {
  default = "*****"
}

variable "aws_secret_key" {
  default = "*********"
}

variable "aws_region" {
  default = "us-east-1"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "public1_sub_cide" {
  default = "10.0.1.0/24"
}

variable "public2_sub_cide" {
  default = "10.0.3.0/24"
}

variable "AZ-1" {
  default = "us-east-1a"
}

variable "AZ-2" {
  default = "us-east-1b"
}

variable "priv_sub_cide" {
  default = "10.0.2.0/24"
}

variable "cidr-0" {
  default = "0.0.0.0/0"
}

variable "ami" {
  default = "ami-0360c520857e3138f"
}

variable "aws_type" {
  default = "t2.micro"
}
```
<br>

outputs.tf: <br>

```
output "vpn_ip" {
  value = aws_instance.vpn.public_ip
}

output "alb_url" {
  value = aws_lb.main.dns_name
}

output "private_ip" {
  value = aws_instance.private.private_ip
}

output "nat_gateway_ip" {
  value = aws_eip.nat.public_ip
}
```
<br>

Запустил: <br>
<img width="1390" height="219" alt="image" src="https://github.com/user-attachments/assets/b9c7a1ff-c40f-4e59-b6f5-edf3a6b2e0ae" /> <br>

<img width="1255" height="293" alt="image" src="https://github.com/user-attachments/assets/6079ac6a-cc3c-4fe1-bc29-f7b132cf282e" /> <br>

<br>

Kрч всё запустилось <br>

<br>

Дальше собвственно приступил к Ansible: <br>

hosts:<br>
```
[vpn]
vpn ansible_host=44.211.167.104 ansible_user=ubuntu

[private]
private ansible_host=10.0.2.55 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/taski.pem ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i ~/.ssh/taski.pem ubuntu@44.211.167.104"'
```
<br>

group_vars/all.yaml:<br>
`ansible_ssh_private_key_file: ~/.ssh/taski.pem`

Дальше надо было все делать через roles:<br>

<img width="193" height="119" alt="image" src="https://github.com/user-attachments/assets/f71822cb-d5ad-46ed-b9fe-d841ad4c0e55" /> <br>

nginx/tasks/main.yaml: <br>
```
---
- name: Update apt cache
  apt:
    update_cache: yes
  register: apt_update
  until: apt_update is succeeded
  retries: 3
  delay: 10

- name: Install nginx without cache update
  apt:
    name: nginx
    state: present
    update_cache: no

- name: Start nginx service
  systemd:
    name: nginx
    state: started
    enabled: yes
```
<br>

grafana/tasks/main.yaml: <br>
```
---
- name: Install prerequisites
  apt:
    name:
      - apt-transport-https
      - software-properties-common
    state: present

- name: Add Grafana GPG key
  apt_key:
    url: https://packages.grafana.com/gpg.key
    state: present

- name: Add Grafana repository
  apt_repository:
    repo: "deb https://packages.grafana.com/oss/deb stable main"
    state: present
    filename: grafana

- name: Update apt cache after adding repository
  apt:
    update_cache: yes

- name: Install grafana
  apt:
    name: grafana
    state: present

- name: Start grafana service
  systemd:
    name: grafana-server
    state: started
    enabled: yes
```

vpn/tasks/main.yaml: <br>
```
---
- name: Install OpenVPN and curl
  apt:
    name:
      - openvpn
      - curl
    state: present
    update_cache: yes

- name: Download OpenVPN install script
  get_url:
    url: https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
    dest: /tmp/openvpn-install.sh
    mode: '0755'

- name: Run OpenVPN installer non-interactively
  shell: |
    export AUTO_INSTALL=y
    export APPROVE_INSTALL=y
    export APPROVE_IP=y
    export IPV6_SUPPORT=n
    export PORT_CHOICE=1
    export PROTOCOL_CHOICE=1
    export DNS=1
    export COMPRESSION_ENABLED=n
    export CUSTOMIZE_ENC=n
    export CLIENT=client
    export PASS=1
    /tmp/openvpn-install.sh
  args:
    creates: /root/client.ovpn

- name: Download client configuration
  fetch:
    src: /root/client.ovpn
    dest: ./client.ovpn
    flat: yes
```

<br>

Ну и сам playbook.yaml: <br>
```
---
- name: Configure VPN server
  hosts: vpn
  become: yes
  roles:
    - vpn

- name: Configure web services
  hosts: private
  become: yes
  roles:
    - nginx
    - grafana
```

<br>

Запустил и проверил: <br>
<img width="1206" height="400" alt="image" src="https://github.com/user-attachments/assets/5f53e41a-424a-4f65-8b60-265bf399de41" /> <br>

<img width="770" height="739" alt="image" src="https://github.com/user-attachments/assets/4c0086c8-d568-4f71-a5c3-8b810cb123b8" />


________________________________________________________________________________________________________________________________
________________________________________________________________________________________________________________________________

Переделал через docker и systemd: <br>

nginx: <br>
```
---
- name: Install Docker
  apt:
    name: docker.io
    state: present

- name: Start Docker service
  systemd:
    name: docker
    state: started
    enabled: yes

- name: Create nginx systemd service
  copy:
    content: |
      [Unit]
      Description=Nginx Docker Container
      Requires=docker.service
      After=docker.service

      [Service]
      Restart=always
      ExecStart=/usr/bin/docker run --name nginx -p 80:80 nginx:alpine
      ExecStop=/usr/bin/docker stop nginx

      [Install]
      WantedBy=multi-user.target
    dest: /etc/systemd/system/nginx-docker.service
    mode: 0644

- name: Reload systemd
  systemd:
    daemon_reload: yes

- name: Start nginx service
  systemd:
    name: nginx-docker
    state: started
    enabled: yes
```
<br>

grafana: <br>
```
---
- name: Install Docker
  apt:
    name: docker.io
    state: present

- name: Start Docker service
  systemd:
    name: docker
    state: started
    enabled: yes

- name: Create grafana systemd service
  copy:
    content: |
      [Unit]
      Description=Grafana Docker Container
      Requires=docker.service
      After=docker.service

      [Service]
      Restart=always
      ExecStart=/usr/bin/docker run --name grafana -p 3000:3000 -e GF_SECURITY_ADMIN_PASSWORD=admin grafana/grafana:latest
      ExecStop=/usr/bin/docker stop grafana

      [Install]
      WantedBy=multi-user.target
    dest: /etc/systemd/system/grafana-docker.service
    mode: 0644

- name: Reload systemd
  systemd:
    daemon_reload: yes

- name: Start grafana service
  systemd:
    name: grafana-docker
    state: started
    enabled: yes
```
Итог: <br>

<br>
<img width="648" height="66" alt="image" src="https://github.com/user-attachments/assets/47a70abe-e68b-4a23-8c3a-755277c62e80" /> <br>

<img width="793" height="551" alt="image" src="https://github.com/user-attachments/assets/c241592f-8bb2-4c0d-a871-64c3f777693d" /> <br>








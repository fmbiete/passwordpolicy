# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box_check_update = true

  config.vm.network "private_network", ip: "192.168.33.10"

  config.vm.synced_folder ".", "/home/vagrant/passwordpolicy"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = 1024
  end

  config.vm.define 'rhel9' do |centos|
    centos.vm.box = "generic/rhel9"

    centos.vm.provision "bootstrap", type: "shell", run: 'never', inline: <<-SHELL
      yum --enablerepo=updates clean metadata
      dnf update -y
      dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
      dnf install -y epel-release
      dnf install -y openssl-devel gcc make redhat-rpm-config ccache krb5-devel clang
      dnf install -y --enablerepo=crb cracklib cracklib-devel cracklib-dicts words
      dnf install -y --enablerepo=crb postgresql18-server postgresql18-libs postgresql18-devel postgresql18-contrib
      mkdict /usr/share/dict/* | packer /var/cache/cracklib/postgresql_dict
      /usr/pgsql-18/bin/postgresql-18-setup initdb
      systemctl start postgresql-18.service
      systemctl enable postgresql-18.service
    SHELL
  end

  config.vm.provision "install", type: "shell", run: 'never', inline: <<-SHELL
    cd /home/vagrant/passwordpolicy
    sudo PATH="/usr/pgsql-18/bin:$PATH" make
    sudo PATH="/usr/pgsql-18/bin:$PATH" make install
    sudo PATH="/usr/pgsql-18/bin:$PATH" make installcheck
    rm passwordpolicy.o passwordpolicy.so
  SHELL
end

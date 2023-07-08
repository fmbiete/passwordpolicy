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
      dnf install -y openssl-devel gcc make redhat-rpm-config ccache
      dnf install -y --enablerepo=crb postgresql15-server postgresql15-libs postgresql15-devel postgresql15-contrib
      dnf install -y --enablerepo-crb install cracklib cracklib-devel cracklib-dicts words
      mkdict /usr/share/dict/* | packer /var/cache/cracklib/postgresql_dict
      # default data directory is '/var/lib/pgsql/15/data/'
      /usr/pgsql-15/bin/postgresql-15-setup initdb
      systemctl start postgresql-15.service
      systemctl enable postgresql-15.service
    SHELL
  end

  config.vm.provision "install", type: "shell", run: 'never', inline: <<-SHELL
    cd /home/vagrant/passwordpolicy
    sudo PATH="/usr/pgsql-15/bin:$PATH" make
    sudo PATH="/usr/pgsql-15/bin:$PATH" make install
    sudo PATH="/usr/pgsql-15/bin:$PATH" make installcheck
    rm passwordpolicy.o passwordpolicy.so
  SHELL
end

# rust_http_0
basic tutorial web server in rust


INSTALL:
POUR la compilation:
apt install build-essential

sudo a2enmod proxy
sudo a2enmod proxy_http
sudo systemctl restart apache2


# compiler et envoyer

cargo build --release ; scp ~/malleable-rust-loader/lib/server-malleable/target/release/malleable-server sliver: ; ssh sliver /root/malleable-server
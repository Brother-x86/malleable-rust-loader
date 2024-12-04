use malleable_rust_loader::dataoperation::un_apply_all_dataoperations;
use malleable_rust_loader::dataoperation::apply_all_dataoperations;
use malleable_rust_loader::dataoperation::DataOperation;

fn main() {
    let data = "salut hello".to_string().into_bytes();
    let mut dataop: Vec<DataOperation>= vec![DataOperation::WEBPAGE, DataOperation::BASE64];
    let m: Vec<u8>  = apply_all_dataoperations(&mut dataop , data).unwrap();
    println!("--{}",std::str::from_utf8(&m).unwrap());
    let dataop= vec![DataOperation::WEBPAGE, DataOperation::BASE64,];
    let ok: Vec<u8>  = un_apply_all_dataoperations(dataop , m).unwrap();
    println!("--{}",std::str::from_utf8(&ok).unwrap());

}
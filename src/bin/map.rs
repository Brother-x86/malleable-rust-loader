use indexmap::{IndexMap,indexmap};


fn main() {
    let mut map = IndexMap::new();
    map.insert("key1", "toto0");
    map.insert("key2", "toto1");
    map.insert("key3", "toto2");
    map.insert("key4", "toto3");
    map.insert("key5", "totototo4");

    let m = indexmap! {
        "yolo1" => 2,
        "yolo2" => 1,
        "yolo3" => 2,
        "yolo4" => 3,
    };

    for (i, key) in map.iter().enumerate() {
        println!("{:?},{:?}",map.get_index(i), &key);

        //*map.get_index_mut(i).unwrap().1 >>= 1;
        //map[i] <<= 1;
    }
    for key in map.keys() {
        println!("{}",key);
        println!("{:?}",map.get(key).unwrap());
    };

    for key in m.keys() {
        println!("{}",key);
        println!("{:?}",m.get(key).unwrap());
    };

}
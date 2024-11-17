use std::collections::BTreeMap;

// type inference lets us omit an explicit type signature (which
// would be `BTreeMap<&str, &str>` in this example).
fn main() {
    let mut movie_reviews = BTreeMap::new();

    // review some movies.
    movie_reviews.insert("Office Space", "Deals with real issues in the workplace.");
    movie_reviews.insert("Pulp Fiction", "Masterpiece.");
    movie_reviews.insert("The Godfather", "Very enjoyable.");
    movie_reviews.insert("The Blues Brothers", "Eye lyked it a lot.");

    // check for a specific one.
    if !movie_reviews.contains_key("Les Misérables") {
        println!(
            "We've got {} reviews, but Les Misérables ain't one.",
            movie_reviews.len()
        );
    }

    // oops, this review has a lot of spelling mistakes, let's delete it.
    movie_reviews.remove("The Blues Brothers");

    // look up the values associated with some keys.
    let to_find = ["Up!", "Office Space"];
    for movie in &to_find {
        match movie_reviews.get(movie) {
            Some(review) => println!("{movie}: {review}"),
            None => println!("{movie} is unreviewed."),
        }
    }

    // Look up the value for a key (will panic if the key is not found).
    println!("Movie review: {}", movie_reviews["Office Space"]);

    // iterate over everything.
    for (movie, review) in &movie_reviews {
        println!("{movie}: \"{review}\"");
    }
}

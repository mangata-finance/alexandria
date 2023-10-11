// @notice Count the number of bits set to 1 in a 256-bit unsigned integer
// @param n The 256-bit unsigned integer
// @return The number of bits set to 1 in n
fn count_ones(n: u256) -> u256 {
    let mut n = n;
    let mut count = 0;
    loop {
        if n == 0 {
            break count;
        }
        n = n & (n - 1);
        count += 1;
    }
}

// @notice Convert a leaf index to an Merkle Mountain Range tree leaf index
// @param n The leaf index
// @return The MMR index
fn leaf_index_to_mmr_index(n: u256) -> u256 {
    2 * n - 1 - count_ones(n - 1)
}

use alexandria_math::math::{shr, shl};
use alexandria_math::sha512::{math_shr_u64, math_shl_u64};
use integer::{u64_wrapping_add, bitwise, downcast, upcast, BoundedInt, U128BitXor};
use traits::{Into, TryInto, BitXor};
use option::OptionTrait;
use result::ResultTrait;
use array::{ArrayTrait, SpanTrait};
use core::clone::Clone;

fn array_of_array(mut b: Span<Span<u8>>, i: usize, j: usize) -> u8 {
    *((*b.at(i)).at(j))
    // b.at(i)
}
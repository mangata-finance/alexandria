use alexandria_math::math::{shr, shl};
use alexandria_math::sha512::{math_shr_u64, math_shl_u64};
use integer::{u64_wrapping_add, bitwise, downcast, upcast, BoundedInt, U128BitXor};
use traits::{Into, TryInto, BitXor};
use option::OptionTrait;
use result::ResultTrait;
use array::{ArrayTrait, SpanTrait};
use core::clone::Clone;

const U64_BIT_NUM: u64 = 64;

const NUM_OF_ROUNDS: usize = 12;

const SIGMA_WIDTH: usize = 16;

// We assume no key, and omit impl for it
const KEY_LENGTH: u8 = 0;

const OUT_LENGTH: u8 = 32;

// const OUT_LENGTH: u8 = 64;



// TODO 
// Implement u64_rotate
// Implement check for t's length it should only be 

// TODO
// Increment loops!!


// Optimization
// Do not clone uselessly
// Maybe the padding function can be a loop? Idt this is imp...
// Use pop_front to replicate array or transform?

// Maybe use span for both input and output on v
// But maybe not for output as we want the array to be moved out of this function
// as the function closes and the array goes out of scope
// It might not even be possible to return a span from a function for this reason
// Unless lifetimes, which I dont remember seeing

fn u64_rotr(x: u64, n: u64) -> u64 {
    let (_, _, or) = bitwise(
        math_shr_u64(x.into(), n.into()).into(),
        math_shl_u64(x.into(), (U64_BIT_NUM - n.into())).into()
    );
    or.try_into().unwrap()
}

fn u64_xor(x: u64, y: u64) -> u64 {
    let (_, xor, _) = bitwise(
        x.into(),
        y.into()
    );
    xor.try_into().unwrap()
}

fn u64_or(x: u64, y: u64) -> u64 {
    let (_, _, or) = bitwise(
        x.into(),
        y.into()
    );
    or.try_into().unwrap()
}

fn u64_and(x: u64, y: u64) -> u64 {
    let (and, _, _) = bitwise(
        x.into(),
        y.into()
    );
    and.try_into().unwrap()
}

// x and y have to be little endian here
fn G(ref v_a: u64,ref v_b: u64,ref v_c: u64,ref v_d: u64, x: u64, y: u64) {

    v_a = u64_wrapping_add(v_a, u64_wrapping_add(v_b, x));

    let v_d_xor_v_a = u64_xor(v_d, v_a);
    // 2^32 = 4294967296
    v_d = u64_or(v_d_xor_v_a/4294967296, TryInto::<u128,u64>::try_into((Into::<u64,u128>::into(v_d_xor_v_a) * 4294967296) % BoundedInt::<u64>::max().into()).unwrap());
    
    v_c = u64_wrapping_add(v_c, v_d);

    let v_b_xor_v_c = u64_xor(v_b, v_c);
    // 2^24 = 16777216, 2^40 = 1099511627776
    v_b = u64_or(v_b_xor_v_c/16777216, TryInto::<u128,u64>::try_into((Into::<u64,u128>::into(v_b_xor_v_c) * 1099511627776) % BoundedInt::<u64>::max().into()).unwrap());

    v_a = u64_wrapping_add(v_a, u64_wrapping_add(v_b, y));

    let v_d_xor_v_a = u64_xor(v_d, v_a);
    // 2^16 = 65536, 2^48 = 281474976710656
    v_d = u64_or(v_d_xor_v_a/65536, TryInto::<u128,u64>::try_into((Into::<u64,u128>::into(v_d_xor_v_a) * 281474976710656) % BoundedInt::<u64>::max().into()).unwrap());

    v_c = u64_wrapping_add(v_c, v_d);

    let v_b_xor_v_c = u64_xor(v_b, v_c);
    // 2^63 = 9223372036854775808, 2^1 = 2
    v_b = u64_or(v_b_xor_v_c/9223372036854775808, TryInto::<u128,u64>::try_into((Into::<u64,u128>::into(v_b_xor_v_c) * 2) % BoundedInt::<u64>::max().into()).unwrap());

}

// each u64 of b has to be little endian here
fn F(ref h_0: u64, ref h_1: u64, ref h_2: u64, ref h_3: u64, ref h_4: u64, ref h_5: u64, ref h_6: u64, ref h_7: u64, b: Span<u64>, t0: u64, t1: u64, f: bool, itr: u128, sigma_span: Span<u8>, iv: Span<u64>){

    let mut v_0:u64 = h_0;
    let mut v_1:u64 = h_1;
    let mut v_2:u64 = h_2;
    let mut v_3:u64 = h_3;
    let mut v_4:u64 = h_4;
    let mut v_5:u64 = h_5;
    let mut v_6:u64 = h_6;
    let mut v_7:u64 = h_7;
    let mut v_8:u64 = *iv.at(0);
    let mut v_9:u64 = *iv.at(1);
    let mut v_10:u64 = *iv.at(2);
    let mut v_11:u64 = *iv.at(3);
    let mut v_12:u64 = u64_xor(*iv.at(4), t0);
    let mut v_13:u64 = u64_xor(*iv.at(5), t1);
    let mut v_14:u64 = if f {
                        u64_xor(*iv.at(6), BoundedInt::<u64>::max())
                    } else {
                        *iv.at(6)
                    };
    let mut v_15:u64 = *iv.at(7);

    let mut i: usize = 0;

    loop{
        if i == NUM_OF_ROUNDS{
            break ;
        };
        
        let s_select: usize = i%10;
        let s_pointer: usize = SIGMA_WIDTH * s_select;

        G(ref v_0,ref v_4,ref v_8,ref v_12,  *b.at((itr*16 + (*sigma_span.at(s_pointer + 0)).into()).try_into().unwrap()) , *b.at((itr*16 + (*sigma_span.at(s_pointer + 1)).into()).try_into().unwrap()));
        G(ref v_1,ref v_5,ref v_9,ref v_13,  *b.at((itr*16 + (*sigma_span.at(s_pointer + 2)).into()).try_into().unwrap()) , *b.at((itr*16 + (*sigma_span.at(s_pointer + 3)).into()).try_into().unwrap()));
        G(ref v_2,ref v_6,ref v_10,ref v_14, *b.at((itr*16 + (*sigma_span.at(s_pointer + 4)).into()).try_into().unwrap()) , *b.at((itr*16 + (*sigma_span.at(s_pointer + 5)).into()).try_into().unwrap()));
        G(ref v_3,ref v_7,ref v_11,ref v_15, *b.at((itr*16 + (*sigma_span.at(s_pointer + 6)).into()).try_into().unwrap()) , *b.at((itr*16 + (*sigma_span.at(s_pointer + 7)).into()).try_into().unwrap()));

        G(ref v_0,ref v_5,ref v_10,ref v_15, *b.at((itr*16 + (*sigma_span.at(s_pointer + 8)).into()).try_into().unwrap()) , *b.at((itr*16 + (*sigma_span.at(s_pointer + 9)).into()).try_into().unwrap()));
        G(ref v_1,ref v_6,ref v_11,ref v_12, *b.at((itr*16 + (*sigma_span.at(s_pointer + 10)).into()).try_into().unwrap()), *b.at((itr*16 + (*sigma_span.at(s_pointer + 11)).into()).try_into().unwrap()));
        G(ref v_2,ref v_7,ref v_8,ref v_13,  *b.at((itr*16 + (*sigma_span.at(s_pointer + 12)).into()).try_into().unwrap()), *b.at((itr*16 + (*sigma_span.at(s_pointer + 13)).into()).try_into().unwrap()));
        G(ref v_3,ref v_4,ref v_9,ref v_14,  *b.at((itr*16 + (*sigma_span.at(s_pointer + 14)).into()).try_into().unwrap()), *b.at((itr*16 + (*sigma_span.at(s_pointer + 15)).into()).try_into().unwrap()));

        i=i+1;
    };

    h_0 = (u64_xor(u64_xor(h_0, v_0), v_8));
    h_1 = (u64_xor(u64_xor(h_1, v_1), v_9));
    h_2 = (u64_xor(u64_xor(h_2, v_2), v_10));
    h_3 = (u64_xor(u64_xor(h_3, v_3), v_11));
    h_4 = (u64_xor(u64_xor(h_4, v_4), v_12));
    h_5 = (u64_xor(u64_xor(h_5, v_5), v_13));
    h_6 = (u64_xor(u64_xor(h_6, v_6), v_14));
    h_7 = (u64_xor(u64_xor(h_7, v_7), v_15));

}

fn add_padding(ref b: Array<u8>) {
    if b.len() == 0 {
        b.append(0x00);
        add_padding(ref b);
    }
    if b.len() % 128 != 0 {
        b.append(0x00);
        add_padding(ref b);
    } 
}

fn get_b_u64_le(data: Span<u8>) -> Array<u64> {
    let mut b_u64_le = ArrayTrait::<u64>::new();
    let mut i = 0;

    loop {
        if (i >= data.len()) {
            break ();
        }
        let new_u64_as_128 = (
            (Into::<u8, u128>::into(*data[i + 7])*72057594037927936_u128)
            + (Into::<u8, u128>::into(*data[i + 6])*281474976710656_u128)
            + (Into::<u8, u128>::into(*data[i + 5])*1099511627776_u128)
            + (Into::<u8, u128>::into(*data[i + 4])*4294967296_u128)
            + (Into::<u8, u128>::into(*data[i + 3])*16777216_u128)
            + (Into::<u8, u128>::into(*data[i + 2])*65536_u128)
            + (Into::<u8, u128>::into(*data[i + 1])*256_u128)
            + (Into::<u8, u128>::into(*data[i + 0]))
            );
        b_u64_le.append(TryInto::<u128,u64>::try_into(new_u64_as_128).unwrap());
        i += 8;
    };
    b_u64_le
}

fn get_out_u8_be(data: Span<u64>) -> Array<u8> {
    let mut arr= ArrayTrait::<u8>::new();

    let mut i: usize = 0;
    loop {
        if i == OUT_LENGTH.into()/8 {
            break ();
        }
        let element_u128:u128 = (*data.at(i)).into();
        arr
            .append(
                (element_u128 & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        arr
            .append(
                ((element_u128/256_u128) & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        arr
            .append(
                ((element_u128/65536_u128) & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        arr
            .append(
                ((element_u128/16777216_u128) & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        arr
            .append(
                ((element_u128/4294967296_u128) & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        arr
            .append(
                ((element_u128/1099511627776_u128) & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        arr
            .append(
                ((element_u128/281474976710656_u128) & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        arr
            .append(
                ((element_u128/72057594037927936_u128) & BoundedInt::<u8>::max().into())
                    .try_into()
                    .unwrap()
            );
        i += 1;
    };
    arr
}

fn blake2b(mut b: Array<u8>) -> Array<u8> {

    let iv = get_iv().span();

    let mut h_0: u64 = u64_xor(
            u64_xor(
                u64_xor(*iv.at(0), 0x01010000), (KEY_LENGTH.into() * 256_u64)
            ),
            Into::<u8,u64>::into(OUT_LENGTH)
        );
    let mut h_1: u64 = *iv.at(1);
    let mut h_2: u64 = *iv.at(2);
    let mut h_3: u64 = *iv.at(3);
    let mut h_4: u64 = *iv.at(4);
    let mut h_5: u64 = *iv.at(5);
    let mut h_6: u64 = *iv.at(6);
    let mut h_7: u64 = *iv.at(7);

    let mut t0:u64 =0;
    let mut t1:u64 =0;

    // Need this to mark last block offset
    let b_len_before_padding = b.len();
    let last_block_offset = b_len_before_padding % 128;

    // Is this even actual since usize will be limiting here not u128_max
    assert(b_len_before_padding.into() < BoundedInt::<u128>::max(), 'Input too long');
    
    add_padding(ref b);

    let b_u64_le = get_b_u64_le(b.span());

    let b_u64_le_len = b_u64_le.len();
    let num_of_blocks = b_u64_le_len/16;

    let sigma_span = get_sigma().span();
    let mut i: u128 = 0;
    loop{
        if i == num_of_blocks.into(){
            break;
        }

        if i != num_of_blocks.into() - 1{
            t0 = u64_wrapping_add(t0, 128);
            if t0 < 128{
                t1 = u64_wrapping_add(t1, 1);
            }

            F(ref h_0, ref h_1, ref h_2, ref h_3, ref h_4, ref h_5, ref h_6, ref h_7, b_u64_le.span(), t0, t1, false, i, sigma_span, iv);
        } else {
            t0 = u64_wrapping_add(t0, last_block_offset.into());
            if t0 < last_block_offset.into(){
                t1 = u64_wrapping_add(t1, 1);
            }
            F(ref h_0, ref h_1, ref h_2, ref h_3, ref h_4, ref h_5, ref h_6, ref h_7, b_u64_le.span(), t0, t1, true, i, sigma_span, iv);
        };

        i = i + 1;
    };

    let mut h_new = ArrayTrait::<u64>::new();
    h_new.append(h_0);
    h_new.append(h_1);
    h_new.append(h_2);
    h_new.append(h_3);
    h_new.append(h_4);
    h_new.append(h_5);
    h_new.append(h_6);
    h_new.append(h_7);

    get_out_u8_be(h_new.span())
}

fn get_iv() -> Array<u64>{

    let mut iv = ArrayTrait::<u64>::new();
    iv.append(0x6A09E667F3BCC908);
    iv.append(0xBB67AE8584CAA73B);
    iv.append(0x3C6EF372FE94F82B);
    iv.append(0xA54FF53A5F1D36F1);
    iv.append(0x510E527FADE682D1);
    iv.append(0x9B05688C2B3E6C1F);
    iv.append(0x1F83D9ABFB41BD6B);
    iv.append(0x5BE0CD19137E2179);

    iv
}

fn get_sigma() -> Array<u8> {
    let mut s = ArrayTrait::<u8>::new();

    // { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }
    s.append(0x00);s.append(0x01);s.append(0x02);s.append(0x03);s.append(0x04);s.append(0x05);s.append(0x06);s.append(0x07);
    s.append(0x08);s.append(0x09);s.append(0x0A);s.append(0x0B);s.append(0x0C);s.append(0x0D);s.append(0x0E);s.append(0x0F);

    // { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    s.append(0x0E);s.append(0x0A);s.append(0x04);s.append(0x08);s.append(0x09);s.append(0x0F);s.append(0x0D);s.append(0x06);
    s.append(0x01);s.append(0x0C);s.append(0x00);s.append(0x02);s.append(0x0B);s.append(0x07);s.append(0x05);s.append(0x03);

    // { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 }
    s.append(0x0B);s.append(0x08);s.append(0x0C);s.append(0x00);s.append(0x05);s.append(0x02);s.append(0x0F);s.append(0x0D);
    s.append(0x0A);s.append(0x0E);s.append(0x03);s.append(0x06);s.append(0x07);s.append(0x01);s.append(0x09);s.append(0x04);

    // { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 }
    s.append(0x07);s.append(0x09);s.append(0x03);s.append(0x01);s.append(0x0D);s.append(0x0C);s.append(0x0B);s.append(0x0E);
    s.append(0x02);s.append(0x06);s.append(0x05);s.append(0x0A);s.append(0x04);s.append(0x00);s.append(0x0F);s.append(0x08);

    // { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 }
    s.append(0x09);s.append(0x00);s.append(0x05);s.append(0x07);s.append(0x02);s.append(0x04);s.append(0x0A);s.append(0x0F);
    s.append(0x0E);s.append(0x01);s.append(0x0B);s.append(0x0C);s.append(0x06);s.append(0x08);s.append(0x03);s.append(0x0D);

    // { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }
    s.append(0x02);s.append(0x0C);s.append(0x06);s.append(0x0A);s.append(0x00);s.append(0x0B);s.append(0x08);s.append(0x03);
    s.append(0x04);s.append(0x0D);s.append(0x07);s.append(0x05);s.append(0x0F);s.append(0x0E);s.append(0x01);s.append(0x09);

    // { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 }
    s.append(0x0C);s.append(0x05);s.append(0x01);s.append(0x0F);s.append(0x0E);s.append(0x0D);s.append(0x04);s.append(0x0A);
    s.append(0x00);s.append(0x07);s.append(0x06);s.append(0x03);s.append(0x09);s.append(0x02);s.append(0x08);s.append(0x0B);

    // { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 }
    s.append(0x0D);s.append(0x0B);s.append(0x07);s.append(0x0E);s.append(0x0C);s.append(0x01);s.append(0x03);s.append(0x09);
    s.append(0x05);s.append(0x00);s.append(0x0F);s.append(0x04);s.append(0x08);s.append(0x06);s.append(0x02);s.append(0x0A);

    // { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 }
    s.append(0x06);s.append(0x0F);s.append(0x0E);s.append(0x09);s.append(0x0B);s.append(0x03);s.append(0x00);s.append(0x08);
    s.append(0x0C);s.append(0x02);s.append(0x0D);s.append(0x07);s.append(0x01);s.append(0x04);s.append(0x0A);s.append(0x05);

    // { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
    s.append(0x0A);s.append(0x02);s.append(0x08);s.append(0x04);s.append(0x07);s.append(0x06);s.append(0x01);s.append(0x05);
    s.append(0x0F);s.append(0x0B);s.append(0x09);s.append(0x0E);s.append(0x03);s.append(0x0C);s.append(0x0D);s.append(0x00);

    s
}

fn convert_u8_array_to_felt252_array(a: Span<u8>) -> Array<felt252>{
    let mut x = ArrayTrait::<felt252>::new();
    let mut i: u32 =0;
    loop{
        if i == a.len(){break;}
        x.append((*a.at(i)).into());
        i=i+1;
    };
    x
}

fn convert_u64_array_to_felt252_array(a: Span<u64>) -> Array<felt252>{
    let mut x = ArrayTrait::<felt252>::new();
    let mut i: u32 =0;
    loop{
        if i == a.len(){break;}
        x.append((*a.at(i)).into());
        i=i+1;
    };
    x
}

fn u8_array_eq(x: Span<u8>, y: Span<u8>) -> bool {
	if x.len() != y.len(){
		return false;
	}

	let mut itr = 0;
	let mut eq = true;
	loop{
		if itr == x.len(){
			break;
		};
		
		if *x.at(itr)!=*y.at(itr){
			eq = false;
			break;
		};
		
		itr = itr +1;
	};
	eq
}
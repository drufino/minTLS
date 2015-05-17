open GF2n
open Utils

module GHASHModulus =
struct
    type elem = bool array

    let lower_modulus = [| true; true; true; false; false; false; false; true |]

    let modulus = Array.init 129 (fun i -> if i < 8 then lower_modulus.(i) else if i == 128 then true else false)

    let var_name= "X"
end


module GF128 = GF2n(GHASHModulus)

let string_of_elt elt =
    let elt = GF128.to_coeffs elt in
    let byte i =
        let bits = Array.sub elt (i*8) 8 in
        Array.fold_left (lor) 0 (Array.mapi (fun i -> fun x -> if not x then 0 else (1 lsl (i))) bits)
    in
    let bytes = List.map byte (range 0 ((Array.length elt) / 8)) in
    let bytes = List.map char_of_int bytes in
    let bytes = List.map reverse_byte bytes in
    string_of_byte_array bytes
;;

let elt_of_string s =
    let bytes = byte_array_of_string s in
    let bytes = Array.map reverse_byte bytes in
    let bit_i i =
        let c    = int_of_char bytes.(i/8) in
        let bit  = (i mod 8) in
        if (c land (1 lsl bit)) = 0 then
            false
        else
            true
    in
    GF128.of_array (Array.init 128 bit_i)
;;

let h  = elt_of_string    "b83b533708bf535d0aa6e52980d53b78" in
let c1 = elt_of_string    "42831ec2217774244b7221b784d0d49c" in
let c2 = elt_of_string    "e3aa212f2c02a4e035c17e2329aca12e" in
let c3 = elt_of_string    "21d514b25466931c7d8f6a5aac84aa05" in
let c4 = elt_of_string    "1ba30b396a0aac973d58e091473f5985" in
let len  = elt_of_string  "00000000000000000000000000000200" in
let ( ** ) = GF128.( ** ) in
let ( ++ ) = GF128.( ++ ) in
let ans = List.fold_left (fun x -> fun y -> (x ++ y) ** h) GF128.zero [c1; c2; c3; c4] in
(*let ans = (len ++ (c1 ** h)) ** h in*)
Printf.printf "%s\n" (string_of_elt ans)
;;

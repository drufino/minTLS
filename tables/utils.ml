(*
 * Copyright (c) 2013, David Rufino <david.rufino@gmail.com>
 * All rights reserved. See LICENSE details.
 *)

open Array

(*external (|>) : 'a -> ('a -> 'b) -> 'b = "%revapply";;*)

let (|>) f g = (fun x -> g (f x))

let rec range i j = if i >= j then [] else i :: (range (i+1) j)

let reverse_byte b = 
  let b = int_of_char b in
  let a = (b * 0x0802) land 0x22110 in
  let c = (b * 0x8020) land 0x88440 in
  char_of_int ((((a lor c) * 0x10101) lsr 16) land 0xff)

let byte_array_of_string s =
  let cnt = (String.length s) / 2 in
  let bytes = Array.init cnt (fun i ->
    let bytes = "0x"^(String.sub s (i*2) 2) in
    char_of_int (int_of_string bytes)
  ) in
  bytes

let string_of_byte_array bytes =
  String.concat "" (List.map (fun byte -> Printf.sprintf "%.2x" (int_of_char byte)) bytes)

let bxor x y =
  if (x && y) then false 
  else if ((not x) && (not y)) then false
  else true

let findrev pred arr =
  let rec findrev_helper i pred arr =
    if i == -1 then
      raise (Failure "error")
    else
      if (pred arr.(i)) then
        i
      else
        findrev_helper (i-1) pred arr
  in
  findrev_helper ((length arr) - 1) pred arr


/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


/**
   File Name:          15.5.4.5-6.js
   ECMA Section:       15.5.4.5 String.prototype.charCodeAt(pos)
   Description:        Returns a number (a nonnegative integer less than 2^16)
   representing the Unicode encoding of the character at
   position pos in this string.  If there is no character
   at that position, the number is NaN.

   When the charCodeAt method is called with one argument
   pos, the following steps are taken:
   1. Call ToString, giving it the theis value as its
   argument
   2. Call ToInteger(pos)
   3. Compute the number of characters in result(1).
   4. If Result(2) is less than 0 or is not less than
   Result(3), return NaN.
   5. Return a value of Number type, of positive sign, whose
   magnitude is the Unicode encoding of one character
   from result 1, namely the characer at position Result
   (2), where the first character in Result(1) is
   considered to be at position 0.

   Note that the charCodeAt function is intentionally
   generic; it does not require that its this value be a
   String object.  Therefore it can be transferred to other
   kinds of objects for use as a method.

   Author:             christine@netscape.com
   Date:               2 october 1997
*/
var SECTION = "15.5.4.5-6";
var VERSION = "ECMA_2";
startTest();
var TITLE   = "String.prototype.charCodeAt";

writeHeaderToLog( SECTION + " "+ TITLE);


new TestCase( SECTION,
	      "var obj = true; obj.__proto__.charCodeAt = String.prototype.charCodeAt; var s = ''; for ( var i = 0; i < 4; i++ ) s+= String.fromCharCode( obj.charCodeAt(i) ); s",
	      "true",
	      eval("var obj = true; obj.__proto__.charCodeAt = String.prototype.charCodeAt; var s = ''; for ( var i = 0; i < 4; i++ ) s+= String.fromCharCode( obj.charCodeAt(i) ); s") );

new TestCase( SECTION,
	      "var obj = 1234; obj.__proto__.charCodeAt = String.prototype.charCodeAt; var s = ''; for ( var i = 0; i < 4; i++ ) s+= String.fromCharCode( obj.charCodeAt(i) ); s",
	      "1234",
	      eval("var obj = 1234; obj.__proto__.charCodeAt = String.prototype.charCodeAt; var s = ''; for ( var i = 0; i < 4; i++ ) s+= String.fromCharCode( obj.charCodeAt(i) ); s") );

new TestCase( SECTION,
	      "var obj = 'hello'; obj.__proto__.charCodeAt = String.prototype.charCodeAt; var s = ''; for ( var i = 0; i < 5; i++ ) s+= String.fromCharCode( obj.charCodeAt(i) ); s",
	      "hello",
	      eval("var obj = 'hello'; obj.__proto__.charCodeAt = String.prototype.charCodeAt; var s = ''; for ( var i = 0; i < 5; i++ ) s+= String.fromCharCode( obj.charCodeAt(i) ); s") );

test();

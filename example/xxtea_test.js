/*jshint node:true, eqeqeq:true */
'use strict';

var xxtea = require('xxtea-node');

var str = "Hello World! 你好，中国！";
var key = "1234567890";
var encrypt_data = xxtea.encrypt(xxtea.toBytes(str), xxtea.toBytes(key));
console.log(new Buffer(encrypt_data).toString('base64'));
var decrypt_data = xxtea.toString(xxtea.decrypt(encrypt_data, xxtea.toBytes(key)));
console.assert(str === decrypt_data);

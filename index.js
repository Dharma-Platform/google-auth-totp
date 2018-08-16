/**
 *   A Time-based One-time Password Algorithm with Google authenticator
 *
 *   - Generate a 80 bits random base 32 secret (i.e. a string with 16 base 32 values)
 *   - Send the secret to the client as QR code generated with googleapis chart
 *   - Display in console the 6 digit code on new 30-seconds intervals from epoch time
 *
 */


'use strict';

var crypto = require('crypto');


var totp = {
    /**
     * Convert a base-32 to hexadecimal with a different base-32 alphabet 
     * from the one used by the parseInt() function
     */
    base32tohex(base32) {

        let base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        let hex = '';
        for (let i = 0; i < base32.length; i++) {
            let val = base32chars.indexOf(base32.charAt(i).toUpperCase());
            bits += (Array(5).fill(0).join('') + val.toString(2)).slice(-5);
        }
        for (let i = 0; i < bits.length - 3; i += 4) {
            let chunk = bits.substr(i, 4);
            hex = hex + parseInt(chunk, 2).toString(16);
        }
        return hex;
    },


    /**
     * Calculate totp for the given secret
     */
    getOTP(secret) {

        // Calculate number of 30-seconds intervals from epoch time, encode this to hex and then 0-pad to obtain a 12 character string. 
        // Finally place this hex string into a buffer and store it into the variable "mssg".
        var mssg = Buffer.from((Array(16).fill(0).join('') + (Math.floor(Math.round(new Date().getTime() / 1000) / 30)).toString(16)).slice(-16), 'hex');

        // Encode the secret from base-32 to hex, place it into a buffer and store it as the variable "key".
        var key = Buffer.from(this.base32tohex(secret), 'hex');

        // FYI - we have stored the message and secret into the buffer because the crypto hmac function requires buffer inputs.

        // Use crypto to obtain an SH1 HMAC digest from the key and mssg
        var hmac = crypto.createHmac('sha1', key); // create Hmac instances
        hmac.setEncoding('hex'); // instruct the Hmac instance that mssg is hex encoded
        hmac.update(mssg);
        hmac.end();
        hmac = hmac.read(); // the SH1 HMAC output
        // Bitwise operations to convert the SH1 HMAC output into a 6 digits code
        return ((parseInt((hmac.substr(parseInt(hmac.slice(-1), 16) * 2, 8)), 16) & 2147483647) + '').slice(-6);
    },



    /**
     * Generate a random base-32 secret
     */
    randomBase32(length) {
        var base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        length = length % 2 === 0 ? length : length + 1; // ensuring even length
        var secret = [];
        for (var i = 0; i < length; i++) {
            secret.push(base32chars.split('')[Math.floor(Math.random() * 32)]);
        }
        return secret.join('');
    },

    /**
     * Generate the shared secret
     */
    generateSharedSecret() {
        return this.randomBase32(16);
    },

    siteIcon: "https://dharma.ai/wp-content/uploads/2018/06/favicon-150x150.png",
    qRCodeSize: "300x300",
    siteDomain: 'dharma.ai',
    siteId: 'Dharma.AI',

    googleChartApiBase: 'https://chart.googleapis.com/chart',

    /**
     * 
     * @param {string} secret 
     * @param {string} user 
     * 
     * Generates a QR Code URL for the user to scan based on the secret and user id (email) passed in.
     */
    generateQrCode(secret, user) {
        const otpAuthUrl = `otpauth://totp/${this.siteId}:${user}?secret=${secret}&issuer=${this.siteId}&image=${this.siteIcon}`;
        return `${this.googleChartApiBase}?chs=${this.qRCodeSize}&chld=M|0&chr=qr&chl=${encodeURIComponent(otpAuthUrl)}`;
    }
};

module.exports = totp;
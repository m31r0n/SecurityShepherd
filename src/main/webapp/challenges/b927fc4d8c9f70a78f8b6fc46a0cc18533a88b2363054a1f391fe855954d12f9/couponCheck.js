/*
 * Client side coupon format check.
 *
 * Coupon codes are secrets and are only validated on the server when an order is placed.
 * This file previously shipped every coupon code to the browser (DES encrypted, with the key
 * in the same file), which disclosed the secret 100% off coupon. It now only performs a basic
 * format check and holds no coupon data.
 */
function checkCoupon(code) {
	if (typeof code !== "string") {
		return false;
	}
	return /^[\x21-\x7e]{4,128}$/.test(code);
}

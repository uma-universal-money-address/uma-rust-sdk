# Changelog

## 0.5.0
- Add the decimals field to payreq paymentinfo for convenience.
- Make the multiplier here a float to match the Currency object in the lnurlp response.
- Bump version to 0.3 since these are breaking changes. Protocol change: uma-universal-money-address/protocol#14

## 0.4.0
- Make the `decimals` field on `Currency` required and change its description to include more details about its use.
- Change the multiplier field from i64 to f64 to allow for very small unit currencies. See https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md for details on why this is needed.

## v0.3.0
- Switch `display_decimals` to `decimals` to better match a LUD-21 proposal after discussions with the author.

## v0.2.0
- Add `display_decimals` to the `Currency` struct in the lnurlp response.

## v0.1.2
- Fix some parameters to be passed by reference.
- Add `travel_rule_format`.

## v0.1.0
- Initial release

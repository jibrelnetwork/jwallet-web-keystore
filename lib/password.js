'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.testPassword = testPassword;

var _zxcvbn2 = require('zxcvbn');

var _zxcvbn3 = _interopRequireDefault(_zxcvbn2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function testPassword(password) {
  var _zxcvbn = (0, _zxcvbn3.default)(password),
      score = _zxcvbn.score,
      feedback = _zxcvbn.feedback;

  return { score: score, feedback: feedback };
}
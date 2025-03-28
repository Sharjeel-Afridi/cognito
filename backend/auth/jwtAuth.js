import request from "request";
import jwkToPem from "jwk-to-pem";
import jwt from "jsonwebtoken";

export default function Validate(req, res, next) {
  let token = req.header("token")?.replace("Bearer ", "");
  if (!token) {
    return res.status(401).send("Access Denied");
  }

  request(
    {
      url: `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
      json: true,
    },
    function (error, response, body) {
      if (!error && response.statusCode === 200) {
        let pems = {};
        let keys = body["keys"];
        for (let key of keys) {
          let jwk = { kty: key.kty, n: key.n, e: key.e };
          pems[key.kid] = jwkToPem(jwk);
        }

        let decodedJwt = jwt.decode(token, { complete: true });
        if (!decodedJwt) return res.status(401).send("Invalid token");

        let pem = pems[decodedJwt.header.kid];
        if (!pem) return res.status(401).send("Invalid token");

        jwt.verify(token, pem, function (err) {
          if (err) return res.status(401).send("Invalid token");
          next();
        });
      } else {
        res.status(500).send("Unable to download JWKs");
      }
    }
  );
};

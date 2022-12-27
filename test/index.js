var rawbody = require('raw-body');

function hasSql(value) {
   

    if (value === null || value === undefined) {
        //console.log('inject error => value unefined');
        return false;
    }

    // sql regex reference: http://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
    var sql_meta = new RegExp('(%27)|(\')|(--)|(%23)|(#)', 'i');
    if (sql_meta.test(value)) {
        return true;
    }

    var sql_meta2 = new RegExp('((%3D)|(=))[^\n]*((%27)|(\')|(--)|(%3B)|(;))', 'i');
    if (sql_meta2.test(value)) {
       // console.log('inject error => sql_meta2');
        return true;
    }

    var sql_typical = new RegExp('w*((%27)|(\'))((%6F)|o|(%4F))((%72)|r|(%52))', 'i');
    if (sql_typical.test(value)) {
       // console.log('inject error => sql_typical');
        return true;
    }

    var sql_union = new RegExp('((%27)|(\'))union', 'i');
    if (sql_union.test(value)) {
       // console.log('inject error => sql_union');
        return true;
    }

    return false;
}

function middleware(req, res, next) {

    var containsSql = false;

    //console.log(111 , req.originalUrl , hasSql(req.originalUrl));
    if (req.originalUrl !== null && req.originalUrl !== undefined) {
        if (hasSql(req.originalUrl) === true) {
            containsSql = true;
        }
    }

    //console.log(222 , req.originalUrl , containsSql, req.method);

    if (containsSql === false) {
        rawbody(req, {
            encoding: 'utf8'
        }, function(err, body) {

            //console.log('222', err,body);
            if (err) {
                return next(err);
            }

           

            if (body !== null && body !== undefined) {

                if (typeof body !== 'string') {
                    console.log('inject error => body-string');
                    body = JSON.stringify(body);
                }

               // console.log(333, body , containsSql);
               // console.log(hasSql(body));

                if (hasSql(body) === true) {
                    console.log('inject error => hassql_body');
                    containsSql = true;
                }
              //  console.log(444 ,containsSql);
            }

            if (containsSql === true) {
                res.status(403).json({
                    //error: 'SQL Detected in Request, Rejected.'
                    error: 'Rejected. 1099922'
                });
            } else {
               // console.log(555);
                next();
            }
        });

       // console.log(666, containsSql, req.method);
       
        //modify 1227
        if(req.method != 'GET'){
            next();
        }
    } else {
        res.status(403).json({
            //error: 'SQL Detected in Request, Rejected.'
            error: 'Rejected. 1099922'
        });
    }
}

module.exports = middleware;

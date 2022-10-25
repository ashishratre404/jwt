const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const users = [
    {
        id: "1",
        username: "john",
        password: "john0908",
        isAdmin: true
    },
    {
        id: "2",
        username: "jane",
        password: "jane0908",
        isAdmin: false
    },
];

let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
    // take refresh token from the user
    const refreshToken = req.body.token;

    //send error if there is no token or invalid token
    if(!refreshToken) return res.status(401).json('you are not authorized');
    if(!refreshTokens.includes(refreshToken)){
        return res.status(403).json('refresh token is not valid')
    }

    jwt.verify(refreshToken, "myRefreshSecteteKye", (err, payload) => {
        err && console.log(err)
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

        const newAccessToken = generateAccessToken(payload);
        const newRefreshToken = generateRefreshToken(payload);

        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            accessToken: newAccessToken, refreshToken: newRefreshToken
        })
    })
})

const generateAccessToken = (user) => {
    return jwt.sign({id:user.id, isAdmin:user.isAdmin}, "mySecteteKye", {expiresIn: "30s"});
}
const generateRefreshToken = (user) => {
    return jwt.sign({id:user.id, isAdmin:user.isAdmin}, "myRefreshSecteteKye");
}

app.post('/api/login', (req, res) => {
    const {username, password} = req.body;
    const user = users.find((u) => {
        return u.username === username && u.password === password;
    })
    if(user){
        // Generate and access token
        const accessToken = generateAccessToken(user)
        const refreshToken = generateRefreshToken(user)
        refreshTokens.push(refreshToken)
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken,
        })
    }else{
        res.status(400).json('username or password incorrect');
    }
});

const verify = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(' ')[1];
        jwt.verify(token, "mySecteteKye", (err, payload) => {
            if(err){
                return res.status(403).json('token is not valid')
            }else{
                req.user = payload;
                next();
            }
        })
    }else{
        res.status(401).json("you are not authorized to access this page")
    }
}

app.delete('/api/users/:userId', verify, (req, res) => {
    if(req.user.id === req.params.userId || req.user.isAdmin){
        res.status(200).json('user has been deleted');
    }else{
        res.status(403).json('you are not allowed to delete user');
    }
})

app.post('/api/logout', verify, (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken)
    res.status(200).json('You logged out successfully')
})

app.listen(5000, () => console.log('server is up and running'));
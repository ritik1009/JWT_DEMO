const express =require('express');
const app = express();
const jwt =require("jsonwebtoken");

const users = [{
    id:"1",
    username:"john",
    password:"john123",
    isAdmin:true
},
{
    id:"2",
    username:"Ritik",
    password:"Ritik123",
    isAdmin:false
}
]

app.use(express.json())

const refreshTokens = []

app.post("/api/refresh",(req,res)=>{
    const refresh_token = req.body.token;
    if(!refresh_token) return res.status(401).json("You are not authenticated");
    if(!refreshTokens.include(refresh_token)){
        return res.status(403).json("Refresh token is not valid!");
    }
    jwt.verify(refresh_token,"myRefreshSecretKey",(err,user)=>{
        err && console.log(err);
        refreshTokens.filter((token)=> token!==refresh_token);
        const newAccessToken = generateAccessToken(user)
        const newRefreshToken = generateRefreshAccessToken(user)
        res.status(200).json({
            accessToken:newAccessToken,
            refreshToken:newRefreshToken,
        })
    })
});



const generateAccessToken = (user)=>{
    return jwt.sign({id:user.id,isAdmin:user.isAdmin},"mySecretKey",{expiresIn:"30s"})
}
const generateRefreshAccessToken = (user)=>{
    return jwt.sign({id:user.id,isAdmin:user.isAdmin},"myRefreshSecretKey")
}


app.post("/api/login",(req,res)=>{
    const {username,password} = req.body;
    const user = users.find(u=>{
        return u.username === username && u.password===password
    })
    if(user){
        const access_token = generateAccessToken(user);
        const refresh_token = generateRefreshAccessToken(user);
        refreshTokens.push(refreshTokens);
        res.json({username,isAdmin:user.isAdmin,access_token,refresh_token});
    }else{
        res.status(400).json("Username or password is incorrect");
    }
})



const verify = (req,res,next)=>{
    const authHeader =req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(" ")[1];

        jwt.verify(token,"mySecretKey",(err,user)=>{
            if(err){
                return res.status(403).json("Token is not Valid.")
            }
            req.user =user;
            next();
        })
    }else{
        res.status(401).json("You are not authenticated")
    }
}



app.delete("/api/users/:userId",verify,(req,res)=>{
    if(req.user.id === req.params.userId || req.user.isAdmin){
        res.status(200).json("user has been deleted.")
    }else{
        res.status(403).json("you are not allowed to delete")
    }
})

app.listen(8800,()=>{
    console.log('Your server available at http://localhost:8800')
})
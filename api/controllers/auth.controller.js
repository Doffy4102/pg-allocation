import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../lib/prisma.js";
import { config } from 'dotenv';
config();


export const register= async (req,res) =>{
    const {username,email,password} =req.body;
    // HASH PASSWORD

    try{

    const hashedPassword= await bcrypt.hash(password, 10);
    console.log(hashedPassword);

    //New USer
    const newUser= await prisma.user.create({
        data: {
            username,
            email,
            password:hashedPassword
        },
    });
    console.log(newUser);
    res.status(201).json({message:"user created succesfully"});
} catch(err){
    console.log(err)
    res.status(500).json({message:"Failed to create a User"});
}

};

export const login = async (req, res) => {
    const { username, password } = req.body;

    try {
        // CHECK IF USER EXISTS
        const user = await prisma.user.findUnique({
            where: { username }
        });

        if (!user) return res.status(401).json({ message: "Invalid Credentials!" });

        // CHECK PASSWORD
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) return res.status(401).json({ message: "Invalid Credentials" });

        // TOKEN GENERATION
        const age = 1000 * 60 * 60 * 24 * 7;
        const token = jwt.sign(
            { id: user.id,
              isAdmin: false,  
             },
            process.env.JWT_SECRET_KEY, // Use the JWT_SECRET_KEY environment variable
            { expiresIn: age }
        );

        const{password:userPassword,...userInfo}=user
        res.cookie("token", token, {
            httpOnly: true,
            // secure:true
            maxAge: age,
        }).status(200).json(userInfo);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Failed to Login!" });
        
    }
};


export const logout= (req,res) =>{
    res.clearCookie("token").status(200).json({message:"Logout Successfull"});
    
}
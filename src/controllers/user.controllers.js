const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const { firstName, lastName, email, password , country, image, frontBaseUrl } = req.body;
    const encriptedPassword = await bcrypt.hash(password, 10);
    const result = await User.create({
        firstName,
        lastName, 
        email, 
        password: encriptedPassword, 
        country, 
        image
    });

    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/${code}`;

    await EmailCode.create({
        code,
        userId: result.id,
    });

    await sendEmail({
        to: email,
        subject: "Verify email for user app",
        html: `
        <h1>Hello ${firstName} ${lastName}</h1>
        <p><a href="${link}">${link}</a></p>
        <p><b> Code: </b> ${code}</p>
        <b>Gracias por iniciar sesion en user App </b>
        `,
    })
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const { firstName, lastName, email, country, image } = req.body;
    const result = await User.update(
        { firstName, lastName, email, country, image },
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyEmail = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({
        where: { code: code }
    });
    if (!emailCode) return res.status(401).json({ message: "Codigo Invalido" });
    const user = await User.update(
        { isVerified: true },
        { where: { id: emailCode.userId }, returning: true }
        );
        await emailCode.destroy();
        return res.json(user[1][0])
});

const login = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne(
        {where: { email: email }}
        ); // validar si existe el email 
    if(!user) return res.status(401).json({message: "Credenciales Invalidas"})
    const isvalid = await bcrypt.compare(password, user.password); //user.password esta es la encriptada
    if(!isvalid) return res.status(401).json({message: "Credenciales invalidas"})
    if (user.isVerified === false) 
        return res.status(401).json({message:"undefined user"});

    const token = jwt.sign( // aqui creamos el token 
        { user },
        process.env.TOKEN_SECRET,
        { expiresIn: '1d' },
    );
    return res.json({user, token})

});

const getLoggedUser = catchError(async(req, res) => {
    return res.json(req.user)

});

const resetPassword = catchError (async(req, res) => {
    const { email, frontBaseUrl } = req.body;
    const user = await User.findOne({where: { email: email }}); 
    
    if(!user) return res.status(401).json({message: "Email no existe"})

    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/${code}`;

    await EmailCode.create({
        code,
        userId: user.id,
    });

    await sendEmail({
        to: email,
        subject: "Verify email for user app",
        html: `
        <h1>Hello ${user.firstName} ${user.lastName}</h1>
        <b>Con el siguiente Link y codigo puedes actualizar tu password</b>
        <p><a href="${link}">${link}</a></p>
        <p><b> Code: </b> ${code}</p>
        <b>Gracias por iniciar sesion en user App </b>
        `,
    })
    return res.status(201).json(user);

});

const updatePassword = catchError(async(req, res) => {
    const { password } = req.body;
    const { code } = req.params;

    const verificar = await EmailCode.findOne({where: {code: code}})
    if (!verificar) return res.status(401).json({ message: "Codigo Invalido" });

    const encriptedPassword = await bcrypt.hash(password, 10);
    const user = await User.update(
        { password: encriptedPassword },
        { where: { id: verificar.userId }, returning: true }
        );

    await verificar.destroy();
    return res.status(201).json(user)


})

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    login,
    getLoggedUser,
    verifyEmail,
    resetPassword,
    updatePassword
}
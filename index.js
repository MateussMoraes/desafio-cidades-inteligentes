import express from "express";
import fs from "node:fs";
import fsPromise from "node:fs/promises"
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { promisify } from "node:util";
import dotenv from "dotenv";

dotenv.config();

let porta = process.env.PORT;
let caminhoDatabase = "./database.json";

export const app = express();

app.use(express.json());

class Usuario {
  #id;
  #nome;
  #email;
  #senha;
  #permissoes;
  #ativo;
  #data_criacao;
  #data_ultimo_login;

  constructor(id, nome, email, senha, permissoes, ativo, data_criacao, data_ultimo_login) {
    this.id = id;
    this.nome = nome;
    this.email = email,
      this.senha = senha,
      this.permissoes = permissoes;
    this.ativo = ativo;
    this.data_criacao = data_criacao;
    this.data_ultimo_login = data_ultimo_login;
  }
}

function validarSenha(senha, erros) {
  let alfabetoMinusculo = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
  let alfabetoMaisculo = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"];
  let numeros = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  let caracteresEspeciais = ["@", "$", "#", "&", "!", "*", "_"];

  let senhaValidar = String(senha);

  if (senhaValidar.length < 8) {
    erros.push({ code: 400, message: "A senha deve ter no mínimo 8 caracteres !" });
  }

  if (!alfabetoMinusculo.some((letra) => senhaValidar.includes(letra))) {
    erros.push({ code: 400, message: "A senha deve ter no mínimo 1 caractere minúsculo!" })
  }

  if (!alfabetoMaisculo.some((letra) => senhaValidar.includes(letra))) {
    erros.push({ code: 400, message: "A senha deve ter no mínimo 1 caractere maiúsculo !" });
  }

  if (!caracteresEspeciais.some((caractere) => senhaValidar.includes(caractere))) {
    erros.push({ code: 400, message: "A senha deve ter no mínimo 1 caractere especial, caracteres aceitos: @, $, #, &, !, *, _" });
  }

  if (!numeros.some((numero) => senha.includes(numero))) {
    erros.push({ code: 400, message: "A senha deve ter no mínimo 1 número !" });
  }
}

function validarEmail(email, erros) {
  if (email.indexOf("@") < 2 || email[email.indexOf("@") - 1] == "." || email[email.indexOf("@") + 1] == "." || email[email.length - 1] == ".") {
    erros.push({ code: 400, message: "Email inválido !" });
  }
}

const middlewareToken = async (req, res, next) => {
  try {
    let auth = req.headers.authorization;

    if (!auth) {
      return res.status(498).json({ code: 498, message: "Token de autenticação não informado !" });
    }

    const [, token] = auth.split(" ");

    jwt.verify(token, process.env.SECRET, (err, success) => {
      if (err) {
        return res.status(498).json({ code: 498, message: "O token de autenticação expirou ou é inválido !" })
      } else {
        req.permissoes = success.permissoes;
        next();
      }
    })

  } catch (error) {
    return res.status(500).json({ error: true, message: "Erro interno do servidor !" });
  }
}

const verificarPermissao = (permissoes, permissao) => {
  return permissoes.includes(permissao);
}

app.post("/usuarios", middlewareToken, async (req, res) => {
  try {

    if (!verificarPermissao(req.permissoes, "CADASTRAR")) {
      return res.status(401).json({ code: 401, message: "Usuário não tem permissão para está operação !"});
    }

    let data = await fsPromise.readFile(caminhoDatabase, { encoding: "utf-8" });
    let database;

    if (data) {
      database = JSON.parse(data);
    } else {
      database = [];
    }

    let { nome, email, senha, permissoes, ativo } = req.body;

    let erros = [];

    if (!nome) erros.push({ code: 400, message: "Nome é obrigatório !" });
    if (!email) erros.push({ code: 400, message: "Email é obrigatório !" });
    if (!senha) erros.push({ code: 400, message: "A senha é obrigatório !" });
    if (!permissoes) erros.push({ code: 400, message: "Permissões é obrigatório !" });
    if (!ativo) erros.push({ code: 400, message: "Ativo é obrigatório" });

    if (typeof nome !== "string") {
      erros.push({ code: 400, message: "O nome deve ser do tipo string !" });
    }

    if (!Array.isArray(permissoes) || permissoes.length > 1 && !permissoes.some((permissao) => permissao === "ATUALIZAR" || permissao === "CADASTRAR" || permissao === "BUSCAR" || permissao === "DELETAR")) {
      erros.push({ code: 400, message: "Permissões deve ser uma lista que pode receber: CADASTRAR, ATUALIZAR, BUSCAR e DELETAR" });
    }

    if (typeof ativo !== "boolean") {
      erros.push({ code: 400, message: "Ativo deve ser do tipo boolean !" });
    }

    validarSenha(senha, erros);

    let senhaCriptografada = bcrypt.hashSync(senha, 6);

    senha = senhaCriptografada;

    validarEmail(email, erros);

    let emailRepetido = database.find((usuario) => usuario.email === email);

    if (emailRepetido) {
      erros.push({ code: 400, message: "Email já cadastrado !" });
    }

    if (erros.length === 0) {

      let id = database.length == 0 ? 1 : database[database.length - 1].id + 1;

      let novoUsuario = new Usuario(id, nome, email, senha, permissoes, ativo, new Date, null);

      database.push(novoUsuario);

      fs.writeFile(caminhoDatabase, JSON.stringify(database), { encoding: "utf-8" }, (error, data) => {
        if (error) {
          console.log(error);
        }
      });

      return res.status(201).json(novoUsuario);
    } else {
      return res.status(400).json({ code: 400, message: erros });
    }
  } catch (error) {
    console.log(error)
    return res.status(500).json({ error: true, message: "Erro interno do servidor !" });
  }
})

app.get("/usuarios", middlewareToken, async (req, res) => {
  try {
    
    if (!verificarPermissao(req.permissoes, "BUSCAR")) {
      return res.status(401).json({ code: 401, message: "Usuário não tem permissão para está operação !"});
    }

    let data = await fsPromise.readFile(caminhoDatabase, { encoding: "utf-8" });
    let database;

    if (data) {
      database = JSON.parse(data);
    } else {
      database = [];
    }

    if (database.length >= 1) {
      return res.status(200).send(database)
    } else {
      return res.status(200).json([]);
    }

  } catch (error) {
    console.log(error)
    return res.status(500).json({ code: 500, message: "Erro interno do servidor !" });
  }
})

app.get("/usuarios/:id", middlewareToken, async (req, res) => {
  try {

    if (!verificarPermissao(req.permissoes, "BUSCAR")) {
      return res.status(401).json({ code: 401, message: "Usuário não tem permissão para está operação !"});
    }

    const { id } = req.params;

    let data = await fsPromise.readFile(caminhoDatabase, { encoding: "utf-8" });
    let database;

    if (data) {
      database = JSON.parse(data);
    } else {
      database = [];
    }

    let buscarPorId = database.find((usuario) => usuario.id === Number(id));

    if (buscarPorId) {
      return res.status(200).send(buscarPorId);
    } else {
      return res.status(404).json({ code: 404, message: "ID inválido ou inexistente, tente novamente !" })
    }

  } catch (error) {
    console.log(error)
    return res.status(500).json({ code: 500, message: "Erro interno do servidor !" });
  }
})

app.patch("/usuarios/:id", middlewareToken, async (req, res) => {
  try {

    if (!verificarPermissao(req.permissoes, "ATUALIZAR")) {
      return res.status(401).json({ code: 401, message: "Usuário não tem permissão para está operação !"});
    }

    let erros = [];

    const { id } = req.params;

    let { email, senha, permissoes } = req.body;

    let data = await fsPromise.readFile(caminhoDatabase, { encoding: "utf-8" });
    let database;

    if (data) {
      database = JSON.parse(data);
    } else {
      database = [];
    }

    let usuario = database.find((usuario) => usuario.id === Number(id));

    if (email) validarEmail(email, erros);

    if (senha) {
      validarSenha(senha, erros)
      let senhaCriptografada = bcrypt.hashSync(senha, 6);

      senha = senhaCriptografada;
    }

    if (permissoes) {
      if (!Array.isArray(permissoes) || !permissoes.some((permissao) => permissao === "ATUALIZAR" || permissao === "CADASTRAR" || permissao === "BUSCAR" || permissao === "DELETAR")) {
        erros.push({ code: 400, message: "Permissões deve ser uma lista que pode receber: CADASTRAR, ATUALIZAR, BUSCAR e DELETAR" });
      }
    }

    if (erros.length == 0) {
      let dados = req.body;

      for (let chaveUsuario in usuario) {
        if (dados[chaveUsuario] == "senha") continue;

        if (dados[chaveUsuario] && dados[chaveUsuario] !== usuario[chaveUsuario]) {
          usuario[chaveUsuario] = dados[chaveUsuario];
        }
      }

      let encontrarIndice = database.findIndex((usuario) => usuario.id === Number(id));

      database[encontrarIndice] = usuario;

      fs.writeFile(caminhoDatabase, JSON.stringify(database), { encoding: "utf-8" }, (error, data) => {
        if (error) {
          console.log(error);
        }
      });

      return res.status(200).json(usuario);
    } else {
      return res.status(400).json({ error: true, message: erros });
    }

  } catch (error) {
    console.log(error)
    return res.status(500).json({ code: 500, message: "Erro interno do servidor !" });
  }
})

app.delete("/usuarios/:id", middlewareToken, async (req, res) => {
  try {

    if (!verificarPermissao(req.permissoes, "DELETAR")) {
      return res.status(401).json({ code: 401, message: "Usuário não tem permissão para está operação !"});
    }

    const { id } = req.params;

    let data = await fsPromise.readFile(caminhoDatabase, { encoding: "utf-8" });
    let database;

    if (data) {
      database = JSON.parse(data);
    } else {
      database = [];
    }

    let usuario = database.find((usuario) => usuario.id === Number(id));

    if (!usuario) {
      return res.status(404).json({ code: 404, message: "ID inválido ou inexistente, tente novamente !" });
    }

    let retirarUsuario = database.filter((usuario) => usuario.id !== Number(id));

    fs.writeFile(caminhoDatabase, JSON.stringify(retirarUsuario), { encoding: "utf-8" }, (error, data) => {
      if (error) {
        console.log(error);
      }
    });

    return res.status(200).json({ message: "Usuário deletado com sucesso !" });
  } catch (error) {
    console.log(error)
    return res.status(500).json({ code: 500, message: "Erro interno do servidor !" });
  }
})

app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ code: 400, message: "Informe os dados corretamente !" });
  }

  let data = await fsPromise.readFile(caminhoDatabase, { encoding: "utf-8" });
  let database;

  if (data) {
    database = JSON.parse(data);
  } else {
    database = [];
  }

  let encontrarUsuario = database.find((usuario) => usuario.email === email);

  if (!encontrarUsuario || !await bcrypt.compare(senha, encontrarUsuario.senha)) {
    return res.status(400).json({ code: 400, message: "Dados incorretos, tente novamente !" });
  }

  if (!encontrarUsuario.ativo) {
    return res.status(400).json({ code: 400, message: "Usuário inativo !" });
  }

  let encontrarIndice = database.findIndex((usuario) => usuario.id === Number(encontrarUsuario.id));

  let dataLogin = new Date();

  encontrarUsuario.data_ultimo_login = dataLogin;

  database[encontrarIndice] = encontrarUsuario;

  fs.writeFile(caminhoDatabase, JSON.stringify(database), { encoding: "utf-8" }, (error, data) => {
    if (error) {
      console.log(error);
    }
  });

  return res.status(200).json({
    token: jwt.sign(
      {
        id: encontrarUsuario.id,
        permissoes: encontrarUsuario.permissoes,
      },
      process.env.SECRET,
      { expiresIn: process.env.EXPIREIN }
    ),
    usuario: {
      id: encontrarUsuario.id,
      nome: encontrarUsuario.nome,
      email: encontrarUsuario.email,
      ativo: encontrarUsuario.ativo,
      permissoes: encontrarUsuario.permissoes,
      data_criacao: encontrarUsuario.data_criacao,
      data_ultimo_login: dataLogin
    }
  })
})

app.listen(porta, () => {
  console.log(`Servidor escutando na porta ${porta}`);
  console.log("Seja bem vindo ao Sistema de Gerenciamento de Usuários !")
})

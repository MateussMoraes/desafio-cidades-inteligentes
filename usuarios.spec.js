import { describe, expect, it, beforeEach, afterAll, afterEach } from '@jest/globals';
import request from 'supertest';
import { app } from './index.js';

let token;
let server;

describe("Testes em login de usuário", () => {

  beforeEach(() => {
    let port = 3004;
    server = app.listen(port);
  })
  
  afterEach(() => {
    server.close();
  })

  it("Deve realizar o login com sucesso, passando um email e senha válido", async () => {
    const dados = await request(app)
      .post("/login")
      .accept("Content-Type", "application/json")
      .send({
        email: "administrador@gmail.com",
        senha: "M@teus123"
      })
      .expect(200)

    expect(dados._body.usuario.nome).toEqual("Administrador");

    token = dados._body.token;
  })

  it("Deve ocorrer um erro ao tentar fazer o login com um usuário e senha inválida", async () => {
    const dados = await request(app)
      .post("/login")
      .accept("Content-Type", "application/json")
      .send({
        email: "administrador412@gmail.com",
        senha: "M@teus123aa1"
      })
      .expect(400)
  })

  it("Deve ocorrer um erro ao tentar realizar o login com um usuário inativo", async () => {
    const dados = await request(app)
      .post("/login")
      .accept("Content-Type", "application/json")
      .send({
        email: "jhondoe@gmail.com",
        senha: "M@teus123"
      })
      .expect(400)
  })
})

describe("Teste em buscas de usuários", () => {
  it("Deve realizar a busca em todos os usuários cadastrados", async () => {
    const dados = await request(app)
      .get("/usuarios")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token}`)
      .expect(200)
  })

  it("Deve ocorrer um erro ao tentar buscar os usuários sem passar o token de autenticação", async () => {
    const dados = await request(app)
      .get("/usuarios")
      .accept("Content-Type", "application/json")
      .expect(498)
  })
})

describe("Teste em buscas de usuários por ID", () => {
  it("Deve realizar a busca de um usuário pelo seu ID", async () => {
    const dados = await request(app)
      .get("/usuarios/1")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token}`)
      .expect(200)
  })

  it("Deve ocorrer um erro ao tentar buscar os usuários por ID sem passar o token de autenticação", async () => {
    const dados = await request(app)
      .get("/usuarios/1")
      .accept("Content-Type", "application/json")
      .expect(498)
  })
})

describe("Teste em cadastro de usuário", () => {
  it("Deve realizar o cadastro de usuário com sucesso", async () => {
    const dados = await request(app)
      .post("/usuarios")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token}`)
      .send({
        nome: "Gustavo",
        email: "gustavo@gmail.com",
        senha: "M@teus123",
        permissoes: [],
        ativo: true
      })
      .expect(201)
  })

  it("Deve ocorrer um erro ao tentar realizar o cadastro de usuário passando um email inválido", async () => {
    const dados = await request(app)
      .post("/usuarios")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token}`)
      .send({
        nome: "Gustavo",
        email: "g@.4gil.com",
        senha: "M@teus123",
        permissoes: [
          "DELETAR",
          "CADASTRAR",
          "ATUALIZAR",
          "BUSCAR"
        ],
        ativo: true
      })
      .expect(400)
  })

  it("Deve ocorrer um erro ao tentar realizar o cadastro de usuário passando uma senha inválida (fraca)", async () => {
    const dados = await request(app)
      .post("/usuarios")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token}`)
      .send({
        nome: "Gustavo",
        email: "gustavo1@gmail.com",
        senha: "mateus123",
        permissoes: [
          "DELETAR",
          "CADASTRAR",
          "ATUALIZAR",
          "BUSCAR"
        ],
        ativo: true
      })
      .expect(400)
  })


  it("Deve ocorrer um erro ao tentar realizar o cadastro de usuário sem passar o token de autenticação", async () => {
    const dados = await request(app)
      .post("/usuarios")
      .accept("Content-Type", "application/json")
      .send({
        nome: "Gustavo",
        email: "gustavo@gmail.com",
        senha: "M@teus123",
        permissoes: [
          "DELETAR",
          "CADASTRAR",
          "ATUALIZAR",
          "BUSCAR"
        ],
        ativo: true
      })
      .expect(498)
  })
})

describe("Teste em atualização de usuário", () => {
  it("Deve atualizar o usuário com sucesso", async () => {
    const dados = await request(app)
      .patch("/usuarios/3")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token}`)
      .send({
        nome: "Adriano",
      })
      .expect(200)
  })

  it("Deve ocorrer um erro atualizar o usuário sem passar o token de autenticação", async () => {
    const dados = await request(app)
      .patch("/usuarios/3")
      .accept("Content-Type", "application/json")
      .send({
        nome: "Adriano",
      })
      .expect(498)
  })
})

describe("Testes de permissões de usuários", () => {

  let token2;

  it("Deve realizar o login com um usuário sem permissões para realizar testes", async () => {
    const dados = await request(app)
      .post("/login")
      .accept("Content-Type", "application/json")
      .send({
        email: "gustavo@gmail.com",
        senha: "M@teus123"
      })
      .expect(200)

    token2 = dados._body.token;
  })


  it("Deve ocorrer um erro ao tentar buscar usuários sem ter a permissão necessária", async () => {
    const dados = await request(app)
      .get("/usuarios")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token2}`)
      .expect(401)
  })

  it("Deve ocorrer um erro ao tentar atualizar usuários sem ter a permissão necessária", async () => {
    const dados = await request(app)
      .patch("/usuarios/3")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token2}`)
      .send({
        email: "gustavo21@gmail.com",
      })
      .expect(401)
  })

  it("Deve ocorrer um erro ao tentar cadastrar usuários sem ter a permissão necessária", async () => {
    const dados = await request(app)
      .post("/usuarios")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token2}`)
      .send({
        nome: "Gustavo",
        email: "gustavo123@gmail.com",
        senha: "M@teus123",
        permissoes: [
          "DELETAR",
          "CADASTRAR",
          "ATUALIZAR",
          "BUSCAR"
        ],
        ativo: true
      })
      .expect(401)
  })

  it("Deve ocorrer um erro ao tentar deletar usuários sem ter a permissão necessária", async () => {
    const dados = await request(app)
      .delete("/usuarios/3")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token2}`)
      .expect(401)
  })

})

describe("Teste em deletar usuários", () => {
  it("Deve deletar o usuário com sucesso", async () => {
    const dados = await request(app)
      .delete("/usuarios/3")
      .accept("Content-Type", "application/json")
      .set("Authorization", `Bearer ${token}`)
      .expect(200)
  })

  it("Deve ocorrer um erro ao deletar o usuário sem passar o token de autenticação", async () => {
    const dados = await request(app)
      .delete("/usuarios/3")
      .accept("Content-Type", "application/json")
      .expect(498)
  })
})
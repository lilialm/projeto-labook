import { UsersDatabase } from "../database/UsersDatabase"
import { CreateUserOutputDTO, DeleteUserOutput, GetUsersOutputDTO, LoginOutputDTO } from "../dtos/UserDTO"
import { BadRequestError } from "../errors/BadRequestError"
import { UserBusinessModel, UserDB, USER_ROLES } from "../interfaces"
import { User } from "../models/User"
import { HashManager } from "../services/HashManager"
import { IdGenerator } from "../services/IdGenerator"
import { TokenManager, TokenPayload } from "../services/TokenManager"

export class UsersBusiness {
  constructor(
    private usersDatabase: UsersDatabase,
    private tokenManager: TokenManager,
    private idGenerator: IdGenerator,
    private hashManager: HashManager
  ) { }

  public getUsers = async (input: GetUsersOutputDTO): Promise<UserBusinessModel[]> => {
    const { token, q } = input

    //permission check
    const payload = this.tokenManager.getPayload(token)
    if (payload === null) {
      throw new BadRequestError("Erro ao fazer Login")
    }
    if (payload.role !== USER_ROLES.ADMIN) {
      throw new BadRequestError("Acesso negado")
    }

    const usersDB: UserDB[] = await this.usersDatabase.getUsers(q)
    const users = usersDB.map((userDB) => {
      const user = new User(
        userDB.id,
        userDB.name,
        userDB.email,
        userDB.password,
        userDB.role,
        userDB.created_at
      )
      return user.toBusinessModel()
    })

    return users
  }

  public signup = async (input: CreateUserOutputDTO): Promise<{}> => {
    const { name, email, password } = input

    if (name.length < 2) {
      throw new BadRequestError("'name' deve ter no mínimo 2 caracteres")
    }
    
    const foundEmail = await this.usersDatabase.getUserByEmail(email)
    if (foundEmail) {
      throw new BadRequestError("Este Email já esta cadastrado")
    }

    const userInstance = new User(
      this.idGenerator.generate(),
      name,
      email,
      await this.hashManager.hash(password),
      USER_ROLES.NORMAL,
      new Date().toISOString()
    )

    await this.usersDatabase.createUser(userInstance.toDBModel())

    const tokenPayload: TokenPayload = {
      id: userInstance.getId(),
      name: userInstance.getName(),
      role: userInstance.getRole()
    }

    const output = {
      token: this.tokenManager.createToken(tokenPayload)
    }

    return output
  }

  public login = async (input: LoginOutputDTO): Promise<{}> => {
    const { email, password } = input

    const userDB: UserDB | undefined = await this.usersDatabase.getUserByEmail(email)

    if (!userDB) {
      throw new BadRequestError("Email não encontrado")
    }

    const passwordHash = await this.hashManager.compare(password, userDB.password)
    if (!passwordHash) {
      throw new BadRequestError("Email ou Senha incorretos")
    }

    const tokenPayload: TokenPayload = {
      id: userDB.id,
      name: userDB.name,
      role: userDB.role
    }

    const output = {
      token: this.tokenManager.createToken(tokenPayload)
    }

    return output
  }

  public deleteUser = async (input: DeleteUserOutput): Promise<void> => {
    const { idToDelete, token } = input
    const userDB = await this.usersDatabase.getUserById(idToDelete)

    if (!userDB) {
      throw new BadRequestError("id não encontrado")
    }

    const payload = this.tokenManager.getPayload(token)
    if (payload === null) {
      throw new BadRequestError("Erro ao fazer login")
    }

    if (payload.role !== USER_ROLES.ADMIN && userDB.id !== payload.id) {
      throw new BadRequestError("Você não tem permissão para fazer essa requisição")
    }

    await this.usersDatabase.deleteUser(idToDelete)
  }
}
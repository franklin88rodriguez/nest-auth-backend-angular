import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs'
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterDto } from './dto/register-user.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      /*desestructurando crateUserDto
      para sacar el password aparte y pasarlo por el metodo hashSync() de la
      libreria bcryptjs*/
      const { password, ...userData } = createUserDto;

      //1 - encriptar la contrasena
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      })

      //2- Guardar el usuario
      await newUser.save();
      /*desestructuramos la respuesta del newUser y le quitamos el password
       dejando solo la propiedad name y email, para esto es necesario
       que el password sea una propiedad opcional en el schema */
      const { password: _, ...user } = newUser.toJSON();

      /*ahora solamente retornanamos una respuesta sin la password, pero en la base
      de datos si se almacena completamente el objeto*/
      return user;

    } catch (error) {
      console.log(error.code);
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} ya existe`)
      }
      throw new InternalServerErrorException('Something terrible happen!!!')
    }
  }

  async register(registerUserDto: RegisterDto): Promise<LoginResponse> {


    const user = await this.create(registerUserDto);


    return {
      user: user,
      token: this.getJwt({ id: user._id })
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email')
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials - password')
    }

    const { password: _, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwt({ id: user.id }),
    }
    /*debe regresar el usuario{_id,name, email, roles}
     y un token (Json WebToken)de acceso*/
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id)
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwt(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
  
}

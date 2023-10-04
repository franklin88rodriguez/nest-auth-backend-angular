import { Controller, Get, Post, Body, Patch, Param, Delete, Request } from '@nestjs/common';
import { UseGuards } from '@nestjs/common/decorators';
import { AuthService } from './auth.service';
import { LoginResponse } from './interfaces/login-response';

// import { UpdateAuthDto } from './dto/update-auth.dto';
// import { CreateUserDto } from './dto/create-user.dto';
// import { LoginDto } from './dto/login.dto';
// import { RegisterDto } from './dto/register-user.dto';

import {LoginDto,RegisterDto, CreateUserDto, UpdateAuthDto } from './dto'
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';
//import { LoginRespones } from '../../dist/auth/interfaces/login-response';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto){
    return this.authService.login(loginDto)
  }

  @Post('/register')
  register(@Body() registerDto: RegisterDto){
    return this.authService.register(registerDto)
  }

  @UseGuards(AuthGuard)
  @Get()
  findAll(@Request() req: Request) {
    //const user = req['user']
    //return user;
    return this.authService.findAll();
  }
  @UseGuards(AuthGuard)
  @Get('/check-token')
  checkToken(@Request() req: Request): LoginResponse{
    const user = req['user'] as User;

    return {
      user,
      token: this.authService.getJwt({id: user._id})
    }
  }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
}

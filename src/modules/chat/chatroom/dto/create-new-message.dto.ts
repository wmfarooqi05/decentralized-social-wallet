import { IsEnum, IsOptional, IsString, IsUUID } from "class-validator";
import { MESSAGE_TYPE } from "../../chat.types";

export class CreateNewMessageDto {
    @IsString()
    messageContent: string;

    @IsEnum(MESSAGE_TYPE)
    messageType: MESSAGE_TYPE;

    @IsString()
    @IsOptional()
    messageRandomId: string;    
}

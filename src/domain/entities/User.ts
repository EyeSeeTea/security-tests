import { Struct } from "./generic/Struct";
import { NamedRef } from "./Ref";

export interface UserAttrs {
    id: string;
    name: string;
    username: string;
    userRoles: UserRole[];
    userGroups: NamedRef[];
}

export interface UserRole extends NamedRef {
    authorities: string[];
}

export class User extends Struct<UserAttrs>() {
    belongToUserGroup(userGroupUid: string): boolean {
        return this.userGroups.some(({ id }) => id === userGroupUid);
    }

    isAdmin(): boolean {
        return this.userRoles.some(({ authorities }) => authorities.includes("ALL"));
    }

    getPassword() {
        const suffix = Math.random();
        const password = "myPassword" + suffix;
        return password;
    }

    getPassword2() {
        const suffix = Math.random();
        const suffix2 = Math.random();
        const password = "myPassword" + suffix + suffix2;
        return password;
    }
}

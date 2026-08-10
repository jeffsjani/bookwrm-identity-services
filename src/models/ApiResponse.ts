export interface ApiResponse<T>{

		success:boolean;

		requestId:string;

		version:string;

		data:T;

}

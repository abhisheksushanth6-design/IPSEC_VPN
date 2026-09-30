/**
 * Authentication and session types.
 */

export interface User {
  id: string;
  name: string;
  email: string;
  username: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login?: string | null;
}

export interface LoginCredentials {
  identifier: string;
  password: string;
}

export interface RegisterData {
  name: string;
  email: string;
  username: string;
  password: string;
}

export interface ForgotPasswordData {
  email: string;
}

export interface ResetPasswordData {
  token: string;
  new_password: string;
}

export interface AuthResponse {
  message: string;
  user: User;
}

export interface ForgotPasswordResponse {
  message: string;
  demo_reset_token?: string;
  demo_reset_url?: string;
}

export interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

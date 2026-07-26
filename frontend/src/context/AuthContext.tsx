import React, { createContext, useContext, useState, useEffect } from "react";
import { api } from "../services/api";
import type { User, TokenResponse } from "../types/auth";

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (usernameOrEmail: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string, role: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem("sentinelx_token"));
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchCurrentUser = async () => {
      const storedToken = localStorage.getItem("sentinelx_token");
      if (storedToken) {
        try {
          const res = await api.get<User>("/auth/me");
          setUser(res.data);
          setToken(storedToken);
        } catch {
          localStorage.removeItem("sentinelx_token");
          setToken(null);
          setUser(null);
        }
      }
      setIsLoading(false);
    };

    fetchCurrentUser();
  }, []);

  const login = async (username_or_email: string, password: string) => {
    const response = await api.post<TokenResponse>("/auth/login/json", {
      username_or_email,
      password,
    });
    const { access_token, user: loggedUser } = response.data;
    localStorage.setItem("sentinelx_token", access_token);
    setToken(access_token);
    setUser(loggedUser);
  };

  const register = async (email: string, username: string, password: string, role: string) => {
    await api.post<User>("/auth/register", {
      email,
      username,
      password,
      role,
    });
  };

  const logout = () => {
    localStorage.removeItem("sentinelx_token");
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user && !!token,
        isLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

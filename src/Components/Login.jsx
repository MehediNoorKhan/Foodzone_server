import React, { useContext, useState } from "react";
import SocialLogin from "./SocialLogin";
import { Link, useLocation, useNavigate } from "react-router";
import { toast } from "react-toastify";
import AuthContext from "../Provider/AuthContext";

const Login = () => {
    const { login } = useContext(AuthContext);
    const location = useLocation();
    const navigate = useNavigate();
    const from = location.state || "/";
    const [loading, setLoading] = useState(false);

    const handleSubmit = (e) => {
        e.preventDefault();
        setLoading(true);
        const form = e.target;
        const email = form.email.value;
        const password = form.password.value;

        login(email, password)
            .then((result) => {
                setLoading(false);
                toast.success("Login successful!");

                const user = result.user;
                const lastVisited = localStorage.getItem(`lastVisited-${user.email}`);

                navigate(lastVisited || "/");
            })
            .catch((error) => {
                setLoading(false);
                toast.error("Invalid credentials");
            });
    };



    return (
        <div className="hero bg-base-200 min-h-screen">
            <div className="hero-content flex-col lg:flex-row-reverse">
                <div className="card bg-base-100 w-full max-w-sm shrink-0 shadow-2xl p-4">
                    <h1 className="text-5xl font-bold text-center">Login Now!</h1>
                    <div className="card-body py-4">
                        <div className="text-sm mt-2 mb-2">
                            Not have an account?{" "}
                            <Link to="/register" className="text-blue-600 hover:underline">
                                Register
                            </Link>
                        </div>
                        <form onSubmit={handleSubmit}>
                            <label className="label">Email</label>
                            <input
                                type="email"
                                name="email"
                                className="input"
                                placeholder="Email"
                                required
                            />
                            <label className="label">Password</label>
                            <input
                                type="password"
                                name="password"
                                className="input"
                                placeholder="Password"
                                required
                            />
                            <button className="btn btn-neutral mt-4 w-full" disabled={loading}>
                                {loading ? "Logging in..." : "Login"}
                            </button>
                        </form>
                        <SocialLogin from={from}></SocialLogin>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Login;

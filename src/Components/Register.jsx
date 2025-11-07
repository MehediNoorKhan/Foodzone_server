import React, { useContext, useState } from "react";
import { Link, useNavigate } from "react-router";
import SocialLogin from "./SocialLogin";
import Swal from "sweetalert2";
import axios from "axios";
import AuthContext from "../Provider/AuthContext";

const Register = () => {
    const { createUser, logout } = useContext(AuthContext);
    const navigate = useNavigate();
    const [ermsg, setErmsg] = useState("");

    const handleSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const formdata = new FormData(form);
        const { email, password, ...rest } = Object.fromEntries(formdata.entries());

        setErmsg("");

        const userinfos = {
            email,
            name: rest.name,
            photourl: rest.photourl,
            membership: "no",
        };

        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const isValidLength = password.length >= 6;

        if (!hasUppercase || !hasLowercase || !isValidLength) {
            setErmsg(
                "Password must contain at least one uppercase letter, one lowercase letter, and be at least 6 characters long."
            );
            Swal.fire({
                icon: "error",
                title: "Invalid Password",
                text: "Password must contain at least one uppercase letter, one lowercase letter, and be at least 6 characters long.",
            });
            return;
        }

        try {
            const userCredential = await createUser(email, password);
            const user = userCredential.user;

            const res = await axios.post("https://ass11github.vercel.app/users", userinfos); // ✅ use your actual endpoint
            if (res.data.insertedId) {
                Swal.fire({
                    position: "top",
                    icon: "success",
                    title: "User has been created successfully",
                    showConfirmButton: false,
                    timer: 1500,
                });

                form.reset();

                await logout();
                navigate("/login");
            }
        } catch (error) {
            setErmsg(error.message);
            Swal.fire({
                icon: "error",
                title: "Something went wrong!",
                text: error.message,
                showConfirmButton: false,
                timer: 1500,
            });
        }
    };

    return (
        <div className="hero bg-base-200 min-h-screen">
            <div className="hero-content flex-col lg:flex-row-reverse">
                <div className="card bg-base-100 w-full max-w-sm shrink-0 shadow-2xl p-4">
                    <h1 className="text-4xl font-bold text-center">Register</h1>
                    <div className="card-body py-4">
                        <div className="text-sm mt-2 mb-2">
                            Already have an account?{" "}
                            <Link to="/login" className="text-blue-600 hover:underline">
                                Login
                            </Link>
                        </div>
                        <form onSubmit={handleSubmit}>
                            <label className="label">Name</label>
                            <input
                                type="text"
                                name="name"
                                className="input input-bordered"
                                placeholder="Your Name"
                                required
                            />

                            <label className="label">Email</label>
                            <input
                                type="email"
                                name="email"
                                className="input input-bordered"
                                placeholder="Email"
                                required
                            />

                            <label className="label">Photo URL</label>
                            <input
                                type="text"
                                name="photourl"
                                className="input input-bordered"
                                placeholder="Photo URL"
                                required
                            />

                            <label className="label">Password</label>
                            <input
                                type="password"
                                name="password"
                                className="input input-bordered"
                                placeholder="Password"
                                required
                            />

                            {ermsg && <p className="text-red-500 mt-1">{ermsg}</p>}

                            <button className="btn btn-neutral mt-4 w-full cursor-pointer">Register</button>
                        </form>

                        <SocialLogin />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Register;

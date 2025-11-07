import React, { useContext, useEffect, useState } from "react";
import { NavLink } from "react-router";
import AuthContext from "../Provider/AuthContext";

const Header = () => {
    const { user, userData, logout } = useContext(AuthContext);
    const [scrolled, setScrolled] = useState(false);

    const handleLogout = () => {
        logout().catch((err) => console.log(err));
    };

    const currentUser = userData?.find(
        (u) => String(u.email) === String(user?.email)
    );

    const links = [
        { to: "/", label: "Home" },
        { to: "/availablefoods", label: "Available Foods" },
        { to: "/addfood", label: "Add Food" },
        { to: "/manage-food", label: "Manage Foods" },
        { to: "/myfoodrequest", label: "My Food Request" },
        { to: "/membership", label: "Membership" },
    ];

    // Scroll listener
    useEffect(() => {
        const handleScroll = () => setScrolled(window.scrollY > 80);
        window.addEventListener("scroll", handleScroll);
        return () => window.removeEventListener("scroll", handleScroll);
    }, []);

    return (
        <header
            className={`fixed w-full z-50 transition-colors duration-500 ${scrolled ? "bg-white shadow-md" : "bg-[#22c55e]"
                }`}
        >
            <div className="max-w-7xl mx-auto flex justify-between items-center px-4 py-3">
                {/* Logo */}
                <NavLink
                    to="/"
                    className={`text-2xl font-bold transition-colors duration-500 ${scrolled ? "text-[#22c55e]" : "text-white"
                        }`}
                >
                    Food Zone
                </NavLink>

                {/* Navbar links for medium and large screens */}
                <nav className="hidden md:flex space-x-6 flex-1 justify-center text-sm md:text-base lg:text-base">
                    {links.map((link) => (
                        <NavLink
                            key={link.to}
                            to={link.to}
                            className={({ isActive }) =>
                                `relative group transition-colors duration-300 ${scrolled
                                    ? "text-gray-500 hover:text-[#24725e]"
                                    : "text-white hover:text-white"
                                }`
                            }
                        >
                            {({ isActive }) => (
                                <>
                                    <span>{link.label}</span>
                                    <span
                                        className={`absolute left-0 bottom-0 h-0.5 w-0 transition-all duration-300 ${isActive ? "w-full" : "group-hover:w-full"
                                            } ${scrolled ? "bg-[#24725e]" : "bg-white"}`}
                                    />
                                </>
                            )}
                        </NavLink>
                    ))}
                </nav>

                {/* Auth Buttons */}
                <div className="hidden md:flex items-center space-x-3">
                    {user ? (
                        <>
                            <div className="relative group">
                                <img
                                    src={
                                        currentUser?.photourl ||
                                        "https://img.daisyui.com/images/profile/demo/spiderperson@192.webp"
                                    }
                                    alt="avatar"
                                    className="w-10 h-10 rounded-full ring-2 ring-white"
                                />
                                <span className="absolute left-1/2 -translate-x-1/2 top-full mt-2 px-2 py-1 text-sm bg-gray-700 text-white rounded opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                                    {currentUser?.name}
                                </span>
                            </div>
                            <button
                                onClick={handleLogout}
                                className={`px-4 py-1 rounded-md border-2 transition-colors duration-300 ${scrolled
                                        ? "border-[#22c55e] text-[#22c55e] hover:bg-[#24725e] hover:text-white"
                                        : "border-white text-white hover:bg-white hover:text-[#22c55e]"
                                    }`}
                            >
                                Log out
                            </button>
                        </>
                    ) : (
                        <>
                            <NavLink to="/login">
                                <button
                                    className={`cursor-pointer px-4 py-1 rounded-md transition-colors duration-300 ${scrolled
                                            ? "bg-[#22c55e] text-white hover:bg-[#24725e]"
                                            : "bg-white text-[#22c55e] hover:bg-green-100"
                                        }`}
                                >
                                    Sign in
                                </button>
                            </NavLink>
                            <NavLink to="/register">
                                <button
                                    className={`cursor-pointer px-4 py-1 rounded-md border-2 transition-colors duration-300 ${scrolled
                                            ? "border-[#22c55e] text-[#22c55e] hover:bg-[#22c55e] hover:text-white"
                                            : "border-white text-white hover:bg-white hover:text-[#22c55e]"
                                        }`}
                                >
                                    Register
                                </button>
                            </NavLink>
                        </>
                    )}
                </div>

                {/* Drawer toggle for small devices */}
                <div className="md:hidden">
                    <input id="nav-drawer" type="checkbox" className="drawer-toggle" />
                    <label
                        htmlFor="nav-drawer"
                        aria-label="open sidebar"
                        className="btn btn-square btn-ghost text-white"
                    >
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            fill="none"
                            viewBox="0 0 24 24"
                            className="inline-block h-6 w-6 stroke-current"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth="2"
                                d="M4 6h16M4 12h16M4 18h16"
                            ></path>
                        </svg>
                    </label>

                    <div className="drawer-side">
                        {/* Blurry transparent overlay */}
                        <label
                            htmlFor="nav-drawer"
                            className="drawer-overlay bg-black bg-opacity-30 backdrop-blur-sm"
                        ></label>

                        <ul className="menu min-h-full w-64 p-4 space-y-2 bg-white/20 backdrop-blur-md text-white">
                            {links.map((link) => (
                                <li key={link.to}>
                                    <NavLink
                                        to={link.to}
                                        className="block px-2 py-2 rounded hover:bg-white/30 hover:text-[#22c55e] transition-colors"
                                    >
                                        {link.label}
                                    </NavLink>
                                </li>
                            ))}

                            {!user && (
                                <li>
                                    <NavLink
                                        to="/register"
                                        className="block px-3 py-2 rounded bg-[#22c55e]/80 text-white hover:bg-[#24725e]/80 text-center transition-colors"
                                    >
                                        Register
                                    </NavLink>
                                </li>
                            )}

                            {user && (
                                <li>
                                    <button
                                        onClick={handleLogout}
                                        className="w-full px-3 py-2 rounded bg-red-500/80 hover:bg-red-600/80 text-white transition-colors"
                                    >
                                        Log out
                                    </button>
                                </li>
                            )}
                        </ul>
                    </div>
                </div>
            </div>
        </header>
    );
};

export default Header;

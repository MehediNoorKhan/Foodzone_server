import React, { useContext, useEffect } from "react";
import { Navigate, useLocation } from "react-router";
import Loader from "./Loader";
import AuthContext from "../Provider/AuthContext";

const PrivateRoute = ({ children }) => {
    const { user, loading } = useContext(AuthContext);
    const location = useLocation();

    useEffect(() => {
        if (user && user.email) {
            localStorage.setItem(`lastVisited-${user.email}`, location.pathname);
        }
    }, [location.pathname, user]);

    if (loading) {
        return <Loader />;
    }

    if (!user) {
        return <Navigate to="/login" />;
    }

    return children;
};

export default PrivateRoute;

import React, { useEffect, useState } from "react";
import auth from "../Firebase/firebase.init.js";
import axios from "axios";
import {
    createUserWithEmailAndPassword,
    GoogleAuthProvider,
    onAuthStateChanged,
    signInWithEmailAndPassword,
    signInWithPopup,
    signOut,
} from "firebase/auth";
import AuthContext from "./AuthContext.jsx";

const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [userData, setUserData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [fetchError, setFetchError] = useState(null);
    const googleProvider = new GoogleAuthProvider();

    // Register new user
    const createUser = (email, password) => {
        setLoading(true);
        return createUserWithEmailAndPassword(auth, email, password);
    };

    // Login user
    const login = (email, password) => {
        setLoading(true);
        return signInWithEmailAndPassword(auth, email, password);
    };

    // Google Sign-In
    const googleSignIn = () => {
        setLoading(true);
        return signInWithPopup(auth, googleProvider);
    };

    // Logout
    const logout = () => {
        setLoading(true);
        return signOut(auth);
    };

    // Fetch users data from backend
    const fetchUsers = async () => {
        try {
            const response = await axios.get("https://ass11github.vercel.app/users");
            setUserData(response.data || []);
            setFetchError(null);
        } catch (error) {
            console.error("Failed to fetch users:", error);

        }
    };

    // Observe auth state
    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
            setUser(currentUser);
            setLoading(false);
            if (currentUser) fetchUsers();
            else setUserData([]);
        });
        return () => unsubscribe();
    }, []);

    const authInfo = {
        user,
        userData,
        loading,
        fetchError,
        createUser,
        login,
        logout,
        googleSignIn,
        setUser,
    };

    return <AuthContext.Provider value={authInfo}>{children}</AuthContext.Provider>;
};

export default AuthProvider;

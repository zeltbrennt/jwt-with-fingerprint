import {Alert, Box, Button, Container, Grow, Stack, TextField, Typography, Zoom} from "@mui/material";
import {FormEvent, useEffect, useState} from "react";

export default function App() {

    const [user, setUser] = useState('')
    const [password, setPassword] = useState('')
    const [isLoggedIn, setIsLoggedIn] = useState(false)
    const [secret, setSecret] = useState('')
    const [secretRevealed, setSecretRevealed] = useState(false)
    const [secretError, setSecretError] = useState(false)

    const handleSubmit = async (e) => {
        e.preventDefault()
        const response = await fetch('http://localhost:8080/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user: user,
                password: password
            }),
            credentials: 'include'
        })
        const data = await response.json()
        sessionStorage.setItem('accessToken', data.token)
        setIsLoggedIn(true)
        setUser('')
        setPassword('')
    }

    const logout = () => {
        setSecret('')
        setIsLoggedIn(false)
        setSecretRevealed(false)
        sessionStorage.removeItem('accessToken')
    }

    const fetchSecret = async () => {
        const awesomeSecret = await fetch('http://localhost:8080/secret', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + sessionStorage.getItem('accessToken')
            },
            credentials: 'include'
        }).then(response => {
            response.ok ? setSecretRevealed(true) : setSecretError(true)
            return response.json()
        }).catch(() => {
            setSecretError(true)
        })
        setSecret(awesomeSecret.value)
    }


    useEffect(() => {
        if (secretError) {
            const timer = setTimeout(() => setSecretError(false), 3000)
            return () => clearTimeout(timer)
        }
    }, [secretError])


    return (
        <Container maxWidth={"sm"}>
            <Box marginTop={5}>
                <Typography variant={"h3"} align={"center"}>Let's test JWT with ✌️</Typography>
                {!isLoggedIn ?
                    <form onSubmit={handleSubmit}>
                        <Stack spacing={2} marginTop={2}>

                            <TextField
                                label={"Username"}
                                onChange={(e) => setUser(e.target.value)}/>
                            <TextField
                                label={"Password"}
                                type={"password"}
                                onChange={(e) => setPassword(e.target.value)}/>
                            <Button
                                variant={"contained"}
                                type={"submit"}>Login</Button>
                        </Stack>
                    </form> :
                    <Stack>
                        <Typography
                            marginTop={5}
                            variant={"h4"}
                            align={"center"}>Welcome back!</Typography>
                        <Button onClick={logout}>Logout</Button>
                    </Stack>
                }
            </Box>
            <Stack marginTop={10} spacing={1}>
                <Button variant={"outlined"}
                        sx={{align: "center"}}
                        onClick={fetchSecret}>Click here to reveal secret</Button>
                <Grow in={secretError}><Alert severity={"error"}>You shall not pass!</Alert></Grow>
                <Zoom in={secretRevealed}>

                    <Typography align={"center"}
                                onClick={() => setSecretRevealed(false)}
                                variant={"h4"}>
                        <Box component={"span"} fontFamily={"serif"}>π</Box> is exactly {secret} 😧</Typography>
                </Zoom>
            </Stack>
        </Container>
    )
}


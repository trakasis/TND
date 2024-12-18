//auth.js
//Helper functions for authentication
export function getAuthToken() {
    return localStorage.getItem('authToken');
}

export function getAuthHeaders() {
    const token = getAuthToken();
    return {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
    };
}

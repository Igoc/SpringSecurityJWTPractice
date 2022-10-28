function logout() {
    if (window.localStorage.getItem('accessToken') == null) {
        alert('로그인 상태가 아닙니다.');
    } else {
        window.localStorage.removeItem('accessToken');
        alert('로그아웃을 성공했습니다.');
    }
}
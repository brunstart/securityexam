package org.example.basicsecurity;

public class UserContext {
    private static final ThreadLocal<User> userThreadLocal = new ThreadLocal<User>();

    // ThreadLocal에게 값을 맡기기 위한 메소드
    public static void setUser(User user)
    {
        userThreadLocal.set(user);
    }

    // ThreadLocal에서 값을 얻어오기 위한 메소드
    public static User getUser() {
        return userThreadLocal.get();
    }

    // ThreadLocal을 초기화 하는 메소드
    public static void clear() {
        userThreadLocal.remove();   // 삭제해주는것 아주 중요
        // 이유 : 쓰레드 풀을 사용하고 있기 때문에 -> 쓰레드가 한 번 사용되고 소멸되지 않고 재사용되기 때문에 값이 유지됨, 재사용을 위해 값을 지워줄 필요가 있음
    }
}

#include <cstdio>
#include <cstddef>
#include <cmath>
#include <algorithm>

size_t numPointsFor(float points) {
    return size_t(ceilf(points) * 2);
}

int main() {
    float attacker_points = 1e38f;
    printf("UNCLAMPED numPoints (would be passed to reserve()/loop) = %zu\n", numPointsFor(attacker_points));

    float points = attacker_points;
    if (!std::isfinite(points) || points < 3.0f) points = 3.0f;
    if (points > 1000.0f) points = 1000.0f;
    printf("CLAMPED points = %f -> numPoints = %zu (safe, bounded allocation)\n", points, numPointsFor(points));
    return 0;
}

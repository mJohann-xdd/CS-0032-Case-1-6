<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../run_clustering.php';

class EuclideanDistanceTest extends TestCase {

    public function testIdenticalPoints() {
        $p1 = [1,2,3];
        $p2 = [1,2,3];
        $this->assertEquals(0, euclideanDistance($p1, $p2));
    }

    public function testPositiveNumbers() {
        $p1 = [1,2];
        $p2 = [4,6];
        $this->assertEquals(5, euclideanDistance($p1, $p2));
    }

    public function testNegativeNumbers() {
        $p1 = [-1,-2];
        $p2 = [-4,-6];
        $this->assertEquals(5, euclideanDistance($p1, $p2));
    }

    public function testDifferentDimensions() {
        $this->expectException(Exception::class);
        $p1 = [1,2];
        $p2 = [1,2,3];
        euclideanDistance($p1, $p2);
    }
}
